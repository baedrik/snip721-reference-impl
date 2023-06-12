#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, to_binary, Addr, Api, Binary, BlockInfo, CanonicalAddr, Coin, Env, OwnedDeps,
        Response, StdError, StdResult, SubMsg, Timestamp, Uint128, WasmMsg,
    };
    use cosmwasm_storage::ReadonlyPrefixedStorage;
    use secret_toolkit::{
        utils::space_pad,
        viewing_key::{ViewingKey, ViewingKeyStore},
    };

    use crate::contract::{check_permission, execute, instantiate, query};
    use crate::expiration::Expiration;
    use crate::inventory::Inventory;
    use crate::msg::{
        AccessLevel, Burn, ContractStatus, ExecuteAnswer, ExecuteMsg, InstantiateConfig,
        InstantiateMsg, Mint, PostInstantiateCallback, QueryAnswer, QueryMsg, ReceiverInfo, Send,
        Transfer, Tx, TxAction,
    };
    use crate::receiver::Snip721ReceiveMsg;
    use crate::state::{
        get_txs, json_load, json_may_load, load, may_load, AuthList, Config, Permission,
        PermissionType, CONFIG_KEY, MINTERS_KEY, PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST,
        PREFIX_INFOS, PREFIX_MAP_TO_ID, PREFIX_MAP_TO_INDEX, PREFIX_OWNER_PRIV, PREFIX_PRIV_META,
        PREFIX_PUB_META, PREFIX_RECEIVERS,
    };
    use crate::token::{Extension, Metadata, Token};

    // Helper functions

    fn init_helper_default() -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("instantiator", &[]);
        let init_msg = InstantiateMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some("admin".to_string()),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: None,
            post_init_callback: None,
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }

    fn init_helper_with_config(
        public_token_supply: bool,
        public_owner: bool,
        enable_sealed_metadata: bool,
        unwrapped_metadata_is_private: bool,
        minter_may_update_metadata: bool,
        owner_may_update_metadata: bool,
        enable_burn: bool,
    ) -> (
        StdResult<Response>,
        OwnedDeps<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies();

        let env = mock_env();
        let init_config: InstantiateConfig = from_binary(&Binary::from(
            format!(
                "{{\"public_token_supply\":{},
            \"public_owner\":{},
            \"enable_sealed_metadata\":{},
            \"unwrapped_metadata_is_private\":{},
            \"minter_may_update_metadata\":{},
            \"owner_may_update_metadata\":{},
            \"enable_burn\":{}}}",
                public_token_supply,
                public_owner,
                enable_sealed_metadata,
                unwrapped_metadata_is_private,
                minter_may_update_metadata,
                owner_may_update_metadata,
                enable_burn,
            )
            .as_bytes(),
        ))
        .unwrap();
        let info = mock_info("instantiator", &[]);
        let init_msg = InstantiateMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some("admin".to_string()),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: Some(init_config),
            post_init_callback: None,
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(_response) => panic!("Expected error, but had Ok response"),
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected error result {:?}", err),
            },
        }
    }

    fn extract_log(resp: StdResult<Response>) -> String {
        match resp {
            Ok(response) => response.attributes[0].value.clone(),
            Err(_err) => "These are not the logs you are looking for".to_string(),
        }
    }

    // Init tests

    #[test]
    fn test_init_sanity() {
        // test default
        let (init_result, deps) = init_helper_default();
        assert_eq!(init_result.unwrap(), Response::default());
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        assert_eq!(config.mint_cnt, 0);
        assert_eq!(config.tx_cnt, 0);
        assert_eq!(config.name, "sec721".to_string());
        assert_eq!(config.admin, deps.api.addr_canonicalize("admin").unwrap());
        assert_eq!(config.symbol, "S721".to_string());
        assert!(!config.token_supply_is_public);
        assert!(!config.owner_is_public);
        assert!(!config.sealed_metadata_is_enabled);
        assert!(!config.unwrap_to_private);
        assert!(config.minter_may_update_metadata);
        assert!(!config.owner_may_update_metadata);
        assert!(!config.burn_is_enabled);

        // test config specification
        let (init_result, deps) =
            init_helper_with_config(true, true, true, true, false, true, false);
        assert_eq!(init_result.unwrap(), Response::default());
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        assert_eq!(config.mint_cnt, 0);
        assert_eq!(config.tx_cnt, 0);
        assert_eq!(config.name, "sec721".to_string());
        assert_eq!(config.admin, deps.api.addr_canonicalize("admin").unwrap());
        assert_eq!(config.symbol, "S721".to_string());
        assert!(config.token_supply_is_public);
        assert!(config.owner_is_public);
        assert!(config.sealed_metadata_is_enabled);
        assert!(config.unwrap_to_private);
        assert!(!config.minter_may_update_metadata);
        assert!(config.owner_may_update_metadata);
        assert!(!config.burn_is_enabled);

        // test post init callback
        let mut deps = mock_dependencies();
        let env = mock_env();
        // just picking a random short HandleMsg that wouldn't really make sense
        let post_init_msg = to_binary(&ExecuteMsg::MakeOwnershipPrivate { padding: None }).unwrap();
        let post_init_send = vec![Coin {
            amount: Uint128::new(100),
            denom: "uscrt".to_string(),
        }];
        let post_init_callback = Some(PostInstantiateCallback {
            msg: post_init_msg.clone(),
            contract_address: "spawner".to_string(),
            code_hash: "spawner hash".to_string(),
            send: post_init_send.clone(),
        });
        let info = mock_info("instantiator", &[]);
        let init_msg = InstantiateMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some("admin".to_string()),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: None,
            post_init_callback,
        };

        let init_response = instantiate(deps.as_mut(), env, info, init_msg).unwrap();
        assert_eq!(
            init_response.messages,
            vec![SubMsg::new(WasmMsg::Execute {
                msg: post_init_msg,
                contract_addr: "spawner".to_string(),
                code_hash: "spawner hash".to_string(),
                funds: post_init_send,
            })]
        );
    }

    // Handle tests

    // test batch mint
    #[test]
    fn test_batch_mint() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let alice = Addr::unchecked("alice".to_string());
        let alice_raw = deps.api.addr_canonicalize(alice.as_str()).unwrap();
        let admin = Addr::unchecked("admin".to_string());
        let admin_raw = deps.api.addr_canonicalize(admin.as_str()).unwrap();
        let pub1 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("NFT1".to_string()),
                description: Some("pub1".to_string()),
                image: Some("uri1".to_string()),
                ..Extension::default()
            }),
        };
        let priv2 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("NFT2".to_string()),
                description: Some("priv2".to_string()),
                image: Some("uri2".to_string()),
                ..Extension::default()
            }),
        };
        let mints = vec![
            Mint {
                token_id: None,
                owner: Some(alice.to_string()),
                public_metadata: Some(pub1.clone()),
                private_metadata: None,
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT2".to_string()),
                owner: None,
                public_metadata: None,
                private_metadata: Some(priv2.clone()),
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT3".to_string()),
                owner: Some(alice.to_string()),
                public_metadata: None,
                private_metadata: None,
                royalty_info: None,
                transferable: None,
                serial_number: None,
                memo: None,
            },
            Mint {
                token_id: None,
                owner: Some(admin.to_string()),
                public_metadata: None,
                private_metadata: None,
                royalty_info: None,
                transferable: None,
                serial_number: None,
                memo: Some("has id 3".to_string()),
            },
        ];
        // test minting when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test non-minter attempt
        let execute_msg = ExecuteMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Only designated minters are allowed to mint"));

        // sanity check
        let execute_msg = ExecuteMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let minted_vec = vec![
            "0".to_string(),
            "NFT2".to_string(),
            "NFT3".to_string(),
            "3".to_string(),
        ];
        let handle_answer: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            ExecuteAnswer::BatchMintNft { token_ids } => {
                assert_eq!(token_ids, minted_vec);
            }
            _ => panic!("unexpected"),
        }

        // verify the tokens are in the id and index maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index1: u32 = load(&map2idx, "0".as_bytes()).unwrap();
        let token_key1 = index1.to_le_bytes();
        let index2: u32 = load(&map2idx, "NFT2".as_bytes()).unwrap();
        let token_key2 = index2.to_le_bytes();
        let index3: u32 = load(&map2idx, "NFT3".as_bytes()).unwrap();
        let token_key3 = index3.to_le_bytes();
        let index4: u32 = load(&map2idx, "3".as_bytes()).unwrap();
        let token_key4 = index4.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id1: String = load(&map2id, &token_key1).unwrap();
        assert_eq!("0".to_string(), id1);
        let id2: String = load(&map2id, &token_key2).unwrap();
        assert_eq!("NFT2".to_string(), id2);
        let id3: String = load(&map2id, &token_key3).unwrap();
        assert_eq!("NFT3".to_string(), id3);
        let id4: String = load(&map2id, &token_key4).unwrap();
        assert_eq!("3".to_string(), id4);
        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &token_key1).unwrap();
        assert_eq!(token1.owner, alice_raw);
        assert_eq!(token1.permissions, Vec::new());
        assert!(token1.unwrapped);
        let token2: Token = json_load(&info_store, &token_key2).unwrap();
        assert_eq!(token2.owner, admin_raw);
        assert_eq!(token2.permissions, Vec::new());
        assert!(token2.unwrapped);
        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta1: Metadata = load(&pub_store, &token_key1).unwrap();
        assert_eq!(pub_meta1, pub1);
        let pub_meta2: Option<Metadata> = may_load(&pub_store, &token_key2).unwrap();
        assert!(pub_meta2.is_none());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta1: Option<Metadata> = may_load(&priv_store, &token_key1).unwrap();
        assert!(priv_meta1.is_none());
        let priv_meta2: Metadata = load(&priv_store, &token_key2).unwrap();
        assert_eq!(priv_meta2, priv2);
        // verify owner lists
        assert!(Inventory::owns(&deps.storage, &alice_raw, 0).unwrap());
        assert!(Inventory::owns(&deps.storage, &alice_raw, 2).unwrap());
        assert!(Inventory::owns(&deps.storage, &admin_raw, 1).unwrap());
        assert!(Inventory::owns(&deps.storage, &admin_raw, 3).unwrap());
        // verify mint tx was logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 4).unwrap();
        assert_eq!(total, 4);
        assert_eq!(txs[0].token_id, "3".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: admin.clone(),
                recipient: admin,
            }
        );
        assert_eq!(txs[0].memo, Some("has id 3".to_string()));

        let execute_msg = ExecuteMsg::BatchMintNft {
            mints,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID NFT2 is already in use"));
    }

    // test minting
    #[test]
    fn test_mint() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        // test minting when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test setting both token_uri and extension
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: Some("uri".to_string()),
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Metadata can not have BOTH token_uri AND extension"));

        // test non-minter attempt
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Only designated minters are allowed to mint"));

        // sanity check
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let pub_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let priv_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFTpriv".to_string()),
                description: Some("Nifty".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub_expect.clone(),
            private_metadata: priv_expect.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let minted = extract_log(handle_result);
        assert!(minted.contains("MyNFT"));
        // verify the token is in the id and index maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // verify all the token info
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let admin_raw = deps.api.addr_canonicalize("admin").unwrap();
        assert_eq!(token.owner, alice_raw);
        assert_eq!(token.permissions, Vec::new());
        assert!(token.unwrapped);
        // verify the token metadata
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, pub_expect.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta, priv_expect.unwrap());
        // verify token is in owner list
        assert!(Inventory::owns(&deps.storage, &alice_raw, 0).unwrap());
        // verify mint tx was logged to both parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: Addr::unchecked("admin".to_string()),
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Mint it baby!".to_string()));
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs, tx2);
        // test minting with an existing token id
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFTpriv".to_string()),
                    description: Some("Nifty".to_string()),
                    image: Some("privuri".to_string()),
                    ..Extension::default()
                }),
            }),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID MyNFT is already in use"));

        // test minting without specifying recipient or id
        let pub_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("AdminNFT".to_string()),
                description: None,
                image: None,
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: None,
            owner: None,
            public_metadata: pub_expect.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Admin wants his own".to_string()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let minted_str = "1".to_string();
        let handle_answer: ExecuteAnswer =
            from_binary(&handle_result.unwrap().data.unwrap()).unwrap();
        match handle_answer {
            ExecuteAnswer::MintNft { token_id } => {
                assert_eq!(token_id, minted_str);
            }
            _ => panic!("unexpected"),
        }

        // verify token is in the token list
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "1".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("1".to_string(), id);
        // verify token info
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        let admin_raw = deps.api.addr_canonicalize("admin").unwrap();
        assert_eq!(token.owner, admin_raw);
        assert_eq!(token.permissions, Vec::new());
        assert!(token.unwrapped);
        // verify metadata
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, pub_expect.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key).unwrap();
        assert!(priv_meta.is_none());
        // verify token is in the owner list
        assert!(Inventory::owns(&deps.storage, &admin_raw, 1).unwrap());
        // verify mint tx was logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &admin_raw, 0, 10).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs.len(), 2);
        assert_eq!(txs[0].token_id, "1".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: Addr::unchecked("admin".to_string()),
                recipient: Addr::unchecked("admin".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Admin wants his own".to_string()));
        assert_eq!(txs[1].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[1].action,
            TxAction::Mint {
                minter: Addr::unchecked("admin".to_string()),
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        assert_eq!(txs[1].memo, Some("Mint it baby!".to_string()));
    }

    // test updating public metadata
    #[test]
    fn test_set_public_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "SNIP20".to_string(),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: SNIP20 not found"));

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "SNIP20".to_string(),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata of token SNIP20"));

        // test setting metadata when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test not minter nor owner
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata"));

        // test owner tries but not allowed to change metadata
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata"));

        // test minter tries, but not allowed
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata"));

        // sanity check: minter updates
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let set_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("New Name".to_string()),
                description: Some("I changed the metadata".to_string()),
                image: Some("new uri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: set_expect.clone(),
            private_metadata: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &0u32.to_le_bytes()).unwrap();
        assert_eq!(pub_meta, set_expect.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &0u32.to_le_bytes()).unwrap();
        assert!(priv_meta.is_none());
    }

    #[test]
    fn test_set_private_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "SNIP20".to_string(),
            public_metadata: None,
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata of token SNIP20"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test trying to change sealed metadata before it has been unwrapped
        let (init_result, mut deps) =
            init_helper_with_config(true, false, true, true, true, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: None,
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The private metadata of a sealed token can not be modified"));

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "SNIP20".to_string(),
            public_metadata: None,
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: SNIP20 not found"));

        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &token_key).unwrap();
        assert!(token.unwrapped);

        // test setting both token_uri and extension
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            private_metadata: Some(Metadata {
                token_uri: Some("uri".to_string()),
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Metadata can not have BOTH token_uri AND extension"));

        // sanity check, minter changing metadata after owner unwrapped
        let set_pub = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("New Name Pub".to_string()),
                description: Some("Minter changed the public metadata".to_string()),
                image: Some("new uri pub".to_string()),
                ..Extension::default()
            }),
        });
        let set_priv = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("New Name Priv".to_string()),
                description: Some("Minter changed the private metadata".to_string()),
                image: Some("new uri priv".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: set_pub.clone(),
            private_metadata: set_priv.clone(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, set_pub.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta, set_priv.unwrap());

        // test setting metadata when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: None,
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: None,
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test owner trying when not authorized
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: None,
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("New Name".to_string()),
                    description: Some("I changed the metadata".to_string()),
                    image: Some("new uri".to_string()),
                    ..Extension::default()
                }),
            }),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Not authorized to update metadata of token MyNFT"));

        // test authorized owner creates new metadata when it didn't exist before
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, true, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let pub_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: None,
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub_expect.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let priv_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("New Name".to_string()),
                description: Some("Owner changed the metadata".to_string()),
                image: Some("new uri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::SetMetadata {
            token_id: "MyNFT".to_string(),
            public_metadata: None,
            private_metadata: priv_expect.clone(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta, priv_expect.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, pub_expect.unwrap());
    }

    // test Reveal
    #[test]
    fn test_reveal() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, true, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token MyNFT"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test reveal when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MySealedNFT".to_string()),
                    description: Some("Sealed metadata test".to_string()),
                    image: Some("sealed_uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test sealed metadata not enabled
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Sealed metadata functionality is not enabled for this contract"));

        // test someone other than owner tries to unwrap
        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let seal_meta = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MySealedNFT".to_string()),
                description: Some("Sealed metadata test".to_string()),
                image: Some("sealed_uri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: seal_meta.clone(),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token MyNFT"));

        // sanity check, unwrap to public metadata
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &token_key).unwrap();
        assert_eq!(pub_meta, seal_meta.clone().unwrap());

        // test trying to unwrap token that has already been unwrapped
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("This token has already been unwrapped"));

        // sanity check, unwrap but keep private
        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, true, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: seal_meta.clone(),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::Reveal {
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &token_key).unwrap();
        assert_eq!(priv_meta, seal_meta.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &token_key).unwrap();
        assert!(pub_meta.is_none());
    }

    // test owner setting approval for specific addresses
    #[test]
    fn test_set_whitelisted_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        let pub1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My1".to_string()),
                description: Some("Public 1".to_string()),
                image: Some("URI 1".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub1.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let pub2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My2".to_string()),
                description: Some("Public 2".to_string()),
                image: Some("URI 2".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub2.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        ); // test burn when status prevents it
        let pub3 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My3".to_string()),
                description: Some("Public 3".to_string()),
                image: Some("URI 3".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub3.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let pub4 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My4".to_string()),
                description: Some("Public 4".to_string()),
                image: Some("URI 4".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub4.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test trying to set approval when status does not allow
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));
        // setting approval is ok even during StopTransactions status
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // only allow the owner to use SetWhitelistedApproval
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        // try approving a token without specifying which token
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // try revoking a token approval without specifying which token
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // sanity check
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let edmund_raw = deps.api.addr_canonicalize("edmund").unwrap();
        let frank_raw = deps.api.addr_canonicalize("frank").unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let nft3_key = 2u32.to_le_bytes();
        let nft4_key = 3u32.to_le_bytes();
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta, pub1.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify it doesn't duplicate any entries if adding permissions that already
        // exist
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta, pub1.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify that setting a token approval with the same expiration as an existing ALL approval, does
        // not modify THAT approval, but continues to process other permission types
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT2 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft2_key).unwrap();
        assert_eq!(pub_meta, pub2.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft2_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT2 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify changing an existing ALL expiration while adding token access
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(1000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm ALL permission with new expiration
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT2 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft2_key).unwrap();
        assert_eq!(pub_meta, pub2.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft2_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists added bob's NFT2 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify default expiration of "never"
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm NFT3 permissions
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists added bob's nft3 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 3);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // verify revoking a token permission that never existed doesn't break anything
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm NFT4 permissions
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists are correct
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 3);
        assert!(!bob_auth.tokens[transfer_idx].contains(&3u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1500000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "edmund".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(2000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );

        // test revoking token permission
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            // expiration is ignored when only performing revoking actions
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm didn't affect ALL permissions
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 3);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT2 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft2_key).unwrap();
        assert_eq!(pub_meta, pub2.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft2_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        assert!(!token.permissions.iter().any(|p| p.address == bob_raw));
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists still has bob, but not with NFT2 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(!bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // test revoking a token permission when address has ALL permission removes the ALL
        // permission, and adds token permissions for all the other tokens not revoked
        // giving them the expiration of the removed ALL permission
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm only bob's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        assert!(!all_perm.iter().any(|p| p.address == bob_raw));
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT1 permission added view_owner for bob with the old ALL permission
        // expiration, and did not touch the existing transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta, pub1.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        // confirm NFT2 permission for bob and charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[transfer_idx], None);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm NFT3 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT4 permission for bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(1000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[transfer_idx], None);
        // confirm AuthLists still has bob, but not with NFT3 view_owner permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_owner_idx].len(), 3);
        assert!(bob_auth.tokens[view_owner_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_owner_idx].contains(&1u32));
        assert!(!bob_auth.tokens[view_owner_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_owner_idx].contains(&3u32));
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // test revoking all view_owner permission
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            // will be ignored but specifying shouldn't screw anything up
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::None),
            view_private_metadata: None,
            transfer: None,
            // will be ignored but specifying shouldn't screw anything up
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm only bob's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        assert!(!all_perm.iter().any(|p| p.address == bob_raw));
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT1 removed view_owner permission for bob, and did not touch the existing
        // transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta, pub1.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        // confirm NFT2 permission removed bob but left and charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        assert!(!token.permissions.iter().any(|p| p.address == bob_raw));
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm NFT3 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT4 permission removed bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists still has bob, but only for NFT1 and 3 transfer permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // test if approving a token for an address that already has ALL permission does
        // nothing if the given expiration is the same
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "edmund".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(2000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm edmund still has ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let edmund_oper_perm = all_perm.iter().find(|p| p.address == edmund_raw).unwrap();
        assert_eq!(
            edmund_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        assert_eq!(edmund_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(edmund_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT4 permissions did not add edmund
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft4_key).unwrap();
        assert_eq!(pub_meta, pub4.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft4_key).unwrap();
        assert!(priv_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm edmund did not get added to AuthList
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        assert!(!auth_list.iter().any(|a| a.address == edmund_raw));

        // test approving a token for an address that already has ALL permission updates that
        // token's permission's expiration, removes ALL permission, and sets token permission
        // for all other tokens using the ALL permission's expiration
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "edmund".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(3000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm edmund's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(!all_perm.iter().any(|p| p.address == edmund_raw));
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1500000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        // confirm NFT1 added permission for edmund,
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT2 added permission for edmund,
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == bob_raw));
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT3 added permission for edmund and that the token data did not get modified
        // and did not touch the existing transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT4 permission added edmund with input expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        // confirm AuthLists added edmund for transferring on every tokens
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 3);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());

        // test that approving a token when the address has an expired ALL permission
        // deletes the ALL permission and performs like a regular ApproveToken (does not
        // add approve permission to all the other tokens)
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::Never),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(2000000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm davids's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let may_oper: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(may_oper.is_none());
        // confirm NFT3 did not add permission for david and that the token data did not get modified
        // and did not touch the existing transfer permission for bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT4 permission added david with input expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm AuthLists added david for transferring on NFT4
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // giving frank ALL permission for later test
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "frank".to_string(),
            // will be ignored but specifying shouldn't screw anything up
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtHeight(5000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm frank's ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let frank_oper_perm = all_perm.iter().find(|p| p.address == frank_raw).unwrap();
        assert_eq!(
            frank_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_oper_perm.expirations[transfer_idx], None);
        // confirm NFT4 did not add permission for frank
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft4_key).unwrap();
        assert_eq!(pub_meta, pub4.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm AuthLists did not add frank
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        assert!(!auth_list.iter().any(|a| a.address == frank_raw));
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // test revoking a token permission when address has ALL permission removes the ALL
        // permission, and adds token permissions for all the other tokens not revoked
        // giving them the expiration of the removed ALL permission
        // This is same as above, but testing when the address has no AuthList already
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "frank".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            transfer: None,
            // this will be ignored
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm frank's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permission added view_owner for frank with the old ALL permission
        // expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let frank_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .unwrap();
        assert_eq!(
            frank_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_tok_perm.expirations[transfer_idx], None);
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta, pub1.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        // confirm NFT2 permission
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let frank_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .unwrap();
        assert_eq!(
            frank_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_tok_perm.expirations[transfer_idx], None);
        // confirm NFT3 permissions do not include frank and that the token data did not get
        // modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT4 permission
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let frank_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == frank_raw)
            .unwrap();
        assert_eq!(
            frank_tok_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(5000))
        );
        assert_eq!(frank_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_tok_perm.expirations[transfer_idx], None);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists added frank with view_owner permissions for all butNFT3
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 5);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());
        let frank_auth = auth_list.iter().find(|a| a.address == frank_raw).unwrap();
        assert_eq!(frank_auth.tokens[view_owner_idx].len(), 3);
        assert!(frank_auth.tokens[view_owner_idx].contains(&0u32));
        assert!(frank_auth.tokens[view_owner_idx].contains(&1u32));
        assert!(frank_auth.tokens[view_owner_idx].contains(&3u32));
        assert!(frank_auth.tokens[view_meta_idx].is_empty());
        assert!(frank_auth.tokens[transfer_idx].is_empty());

        // test granting ALL permission when the address has some token permissions
        // This should remove all the token permissions and the AuthList
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "frank".to_string(),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtHeight(2500)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm frank's ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let frank_oper_perm = all_perm.iter().find(|p| p.address == frank_raw).unwrap();
        assert_eq!(
            frank_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtHeight(2500))
        );
        assert_eq!(frank_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(frank_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT2 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        // confirm NFT4 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists removed frank
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        assert!(!auth_list.iter().any(|a| a.address == frank_raw));
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // test revoking all permissions when address has ALL
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "frank".to_string(),
            token_id: None,
            view_owner: Some(AccessLevel::None),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm frank's ALL permission is gone
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm NFT2 permission removed frank
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm NFT4 permission removed frank
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        assert!(!token.permissions.iter().any(|p| p.address == frank_raw));
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(3000))
        );
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists removed frank
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 4);
        assert!(!auth_list.iter().any(|a| a.address == frank_raw));
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 2);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&1u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let edmund_auth = auth_list.iter().find(|a| a.address == edmund_raw).unwrap();
        assert_eq!(edmund_auth.tokens[transfer_idx].len(), 4);
        assert!(edmund_auth.tokens[transfer_idx].contains(&0u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&1u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&2u32));
        assert!(edmund_auth.tokens[transfer_idx].contains(&3u32));
        assert!(edmund_auth.tokens[view_meta_idx].is_empty());
        assert!(edmund_auth.tokens[view_owner_idx].is_empty());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&3u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());

        // test revoking a token which is address' last permission
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::RevokeToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm NFT2 permission removed charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        assert!(!token.permissions.iter().any(|p| p.address == charlie_raw));
        let edmund_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == edmund_raw)
            .unwrap();
        assert_eq!(edmund_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(edmund_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            edmund_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(2000))
        );
        // confirm AuthLists removed charlie
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert!(!auth_list.iter().any(|a| a.address == charlie_raw));

        // verify that storage entry for AuthLists gets removed when all are gone
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "edmund".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // verify no ALL permissions left
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT2 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT3 permissions are empty (and info is intact)
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.clone().unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm NFT4 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // verify no AuthLists left
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // verify revoking doesn't break anything when there are no permissions
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "edmund".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::None),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // verify no ALL permissions left
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm NFT1 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT2 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm NFT3 permissions are empty (and info is intact)
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft3_key).unwrap();
        assert_eq!(pub_meta, pub3.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft3_key).unwrap();
        assert!(priv_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm NFT4 permissions are empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft4_key).unwrap();
        assert!(token.permissions.is_empty());
        // verify no AuthLists left
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
    }

    // test approve from the cw721 spec
    #[test]
    fn test_cw721_approve() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, true, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::Approve {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::Approve {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("Not authorized to grant/revoke transfer permission for token MyNFT")
        );

        let priv_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: Some("metadata".to_string()),
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv_expect.clone(),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test contract status does not allow
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::Approve {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test unauthorized address attempt
        let execute_msg = ExecuteMsg::Approve {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("Not authorized to grant/revoke transfer permission for token MyNFT")
        );

        // test expired operator attempt
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("MyNFT".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(500000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(2000000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Transfer authority for all tokens of alice has expired"));

        let tok_key = 0u32.to_le_bytes();
        let tok2_key = 1u32.to_le_bytes();
        let tok3_key = 2u32.to_le_bytes();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();

        // test operator tries to grant permission to another operator.  This should
        // not do anything but end successfully
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm charlie still has ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let charlie_oper_perm = all_perm.iter().find(|p| p.address == charlie_raw).unwrap();
        assert_eq!(
            charlie_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(500000))
        );
        assert_eq!(charlie_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_oper_perm.expirations[view_owner_idx], None);
        // confirm token permission did not add charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm charlie did not get added to Authlist
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check:  operator sets approval for an expired operator
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(750000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm charlie's expired ALL permission was removed
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(!all_perm.iter().any(|p| p.address == charlie_raw));
        // confirm token permission added charlie with default expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv_expect.clone().unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthList added charlie
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&0u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());

        // sanity check:  owner sets approval for an operator with only that one token
        let execute_msg = ExecuteMsg::Approve {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(200)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm bob's ALL permission was removed
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm token permission added bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv_expect.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(200))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthList added bob
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // used to test auto-setting individual token permissions when only one token
        // of many is approved with a different expiration than an operator's expiration
        let priv2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT2".to_string()),
                description: Some("metadata2".to_string()),
                image: Some("uri2".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv2.clone(),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT3".to_string()),
                    description: Some("metadata3".to_string()),
                    image: Some("uri3".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm david is an operator
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let execute_msg = ExecuteMsg::Approve {
            spender: "david".to_string(),
            token_id: "MyNFT2".to_string(),
            expires: Some(Expiration::AtHeight(300)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm david's ALL permission was removed
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm MyNFT token permission added david with ALL permission's expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.permissions.len(), 3);
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm MyNFT2 token permission added david with input expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(300))
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok2_key).unwrap();
        assert_eq!(priv_meta, priv2.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok2_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm MyNFT3 token permission added david with ALL permission's expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok3_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthList added david
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 3);
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 3);
        assert!(david_auth.tokens[transfer_idx].contains(&0u32));
        assert!(david_auth.tokens[transfer_idx].contains(&1u32));
        assert!(david_auth.tokens[transfer_idx].contains(&2u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());
    }

    // test Revoke from cw721 spec
    #[test]
    fn test_cw721_revoke() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::Revoke {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::Revoke {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("Not authorized to grant/revoke transfer permission for token MyNFT")
        );

        let priv_expect = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: Some("metadata".to_string()),
                image: Some("uri".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv_expect.clone(),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test contract status does not allow
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::Revoke {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test unauthorized address attempt
        let execute_msg = ExecuteMsg::Revoke {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("Not authorized to grant/revoke transfer permission for token MyNFT")
        );

        // test expired operator attempt
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("MyNFT".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(500000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::Revoke {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(2000000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Transfer authority for all tokens of alice has expired"));

        let tok_key = 0u32.to_le_bytes();
        let tok2_key = 1u32.to_le_bytes();
        let tok3_key = 2u32.to_le_bytes();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();

        // test operator tries to revoke permission from another operator
        let execute_msg = ExecuteMsg::Revoke {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(1000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Can not revoke transfer permission from an existing operator"));

        // sanity check:  operator revokes approval from an expired operator will delete
        // the expired ALL permission
        let execute_msg = ExecuteMsg::Revoke {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(750000),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm charlie's expired ALL permission was removed
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(!all_perm.iter().any(|p| p.address == charlie_raw));
        // confirm token permission is still empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert!(token.permissions.is_empty());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv_expect.clone().unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm AuthList is still empty
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: operator approves, then revokes
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(200)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm charlie does not have ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(!all_perm.iter().any(|p| p.address == charlie_raw));
        // confirm token permission added charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(200))
        );
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let execute_msg = ExecuteMsg::Revoke {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm charlie does not have ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(!all_perm.iter().any(|p| p.address == charlie_raw));
        // confirm token permission removed charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv_expect.clone().unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm AuthList removed charlie
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // verify revoking a non-existent permission does not break anything
        let execute_msg = ExecuteMsg::Revoke {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm charlie does not have ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        assert!(!all_perm.iter().any(|p| p.address == charlie_raw));
        // confirm token does not list charlie
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv_expect.clone().unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm AuthList doesn not contain charlie
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check:  owner revokes token approval for an operator with only that one token
        let execute_msg = ExecuteMsg::Revoke {
            spender: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm bob's ALL permission was removed
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm token permission is empty
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv_expect.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        assert!(token.permissions.is_empty());
        // confirm AuthList does not contain bob
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // used to test auto-setting individual token permissions when only one token
        // of many is revoked from an operator
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let priv2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT2".to_string()),
                description: Some("metadata2".to_string()),
                image: Some("uri2".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv2.clone(),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT3".to_string()),
                    description: Some("metadata3".to_string()),
                    image: Some("uri3".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::Never),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm david is an operator
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let david_oper_perm = all_perm.iter().find(|p| p.address == david_raw).unwrap();
        assert_eq!(
            david_oper_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(david_oper_perm.expirations[view_owner_idx], None);
        let execute_msg = ExecuteMsg::Revoke {
            spender: "david".to_string(),
            token_id: "MyNFT2".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm david's ALL permission was removed
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Option<Vec<Permission>> = json_may_load(&all_store, alice_key).unwrap();
        assert!(all_perm.is_none());
        // confirm MyNFT token permission added david with ALL permission's expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm MyNFT2 token permission does not contain david
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok2_key).unwrap();
        assert!(token.permissions.is_empty());
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok2_key).unwrap();
        assert_eq!(priv_meta, priv2.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok2_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm MyNFT3 token permission added david with ALL permission's expiration
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok3_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let david_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == david_raw)
            .unwrap();
        assert_eq!(
            david_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        assert_eq!(david_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(david_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthList added david
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 2);
        assert!(david_auth.tokens[transfer_idx].contains(&0u32));
        assert!(!david_auth.tokens[transfer_idx].contains(&1u32));
        assert!(david_auth.tokens[transfer_idx].contains(&2u32));
        assert!(david_auth.tokens[view_meta_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());
    }

    // test burn
    #[test]
    fn test_burn() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("metadata".to_string()),
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test burn when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test when burn is disabled
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token"));

        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("privmetadata".to_string()),
                    image: Some("privuri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("pubmetadata".to_string()),
                    image: Some("puburi".to_string()),
                    ..Extension::default()
                }),
            }),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test unauthorized addres
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        // test expired token approval
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("charlie", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to token MyNFT has expired"));

        // test expired ALL approval
        let execute_msg = ExecuteMsg::ApproveAll {
            operator: "bob".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to all tokens of alice has expired"));

        let tok_key = 0u32.to_le_bytes();
        let tok2_key = 1u32.to_le_bytes();
        let tok3_key = 2u32.to_le_bytes();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();

        // sanity check: operator burns
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT".to_string(),
            memo: Some("Burn, baby, burn!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm token was removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: Option<u32> = may_load(&map2idx, "MyNFT".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: Option<String> = may_load(&map2id, &tok_key).unwrap();
        assert!(id.is_none());
        // confirm token info was deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Option<Token> = json_may_load(&info_store, &tok_key).unwrap();
        assert!(token.is_none());
        // confirm the metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &tok_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm the tx was logged to both parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: Addr::unchecked("alice".to_string()),
                burner: Some(Addr::unchecked("bob".to_string())),
            }
        );
        assert_eq!(txs[0].memo, Some("Burn, baby, burn!".to_string()));
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs, tx2);
        // confirm charlie's AuthList was removed because the only token was burned
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm the token was removed from the owner's list
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());

        let transfer_idx = PermissionType::Transfer.to_usize();

        let priv2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT2".to_string()),
                description: Some("privmetadata2".to_string()),
                image: Some("privuri2".to_string()),
                ..Extension::default()
            }),
        });
        let pub2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT2".to_string()),
                description: Some("pubmetadata2".to_string()),
                image: Some("puburi2".to_string()),
                ..Extension::default()
            }),
        });
        // sanity check: address with token permission burns it
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv2,
            public_metadata: pub2,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let priv3 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT3".to_string()),
                description: Some("privmetadata3".to_string()),
                image: Some("privuri3".to_string()),
                ..Extension::default()
            }),
        });
        let pub3 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT3".to_string()),
                description: Some("pubmetadata3".to_string()),
                image: Some("puburi3".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv3.clone(),
            public_metadata: pub3.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT2".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::Approve {
            spender: "david".to_string(),
            token_id: "MyNFT3".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT2".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("charlie", &[]),
            execute_msg,
        );
        // confirm token was removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: Option<u32> = may_load(&map2idx, "MyNFT2".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: Option<String> = may_load(&map2id, &1u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        // confirm token info was deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Option<Token> = json_may_load(&info_store, &tok2_key).unwrap();
        assert!(token.is_none());
        // confirm MyNFT3 is intact
        let token: Token = json_load(&info_store, &tok3_key).unwrap();
        let david_perm = token.permissions.iter().find(|p| p.address == david_raw);
        assert!(david_perm.is_some());
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok3_key).unwrap();
        assert_eq!(priv_meta, priv3.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &tok3_key).unwrap();
        assert_eq!(pub_meta, pub3.unwrap());
        // confirm the MyNFT2 metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &tok2_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok2_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm the tx was logged to both parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 5);
        assert_eq!(txs[0].token_id, "MyNFT2".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: Addr::unchecked("alice".to_string()),
                burner: Some(Addr::unchecked("charlie".to_string())),
            }
        );
        assert!(txs[0].memo.is_none());
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs, tx2);
        // confirm charlie's AuthList was removed because his only approved token was burned
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let charlie_auth = auth_list.iter().find(|a| a.address == charlie_raw);
        assert!(charlie_auth.is_none());
        let david_auth = auth_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[transfer_idx].len(), 1);
        assert!(david_auth.tokens[transfer_idx].contains(&2u32));
        // confirm the token was removed from the owner's list
        assert!(!Inventory::owns(&deps.storage, &alice_raw, 1).unwrap());
        assert!(Inventory::owns(&deps.storage, &alice_raw, 2).unwrap());

        // sanity check: owner burns
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "MyNFT3".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm token was removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: Option<u32> = may_load(&map2idx, "MyNFT3".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: Option<String> = may_load(&map2id, &2u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        // confirm token info was deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Option<Token> = json_may_load(&info_store, &tok3_key).unwrap();
        assert!(token.is_none());
        // confirm the metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &tok3_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok3_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm the tx was logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 6);
        assert_eq!(txs[0].token_id, "MyNFT3".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: Addr::unchecked("alice".to_string()),
                burner: None,
            }
        );
        assert!(txs[0].memo.is_none());
        // confirm david's AuthList was removed because the only token was burned
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm the token was removed from the owner's list
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 2).unwrap());
    }

    // test batch burn
    #[test]
    fn test_batch_burn() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test burn when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "NFT1".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test when burn is disabled
        let execute_msg = ExecuteMsg::BurnNft {
            token_id: "NFT1".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Burn functionality is not enabled for this token"));

        // set up for batch burn test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let priv3 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT3".to_string()),
                description: Some("privmetadata3".to_string()),
                image: Some("privuri3".to_string()),
                ..Extension::default()
            }),
        });
        let pub3 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT3".to_string()),
                description: Some("pubmetadata3".to_string()),
                image: Some("puburi3".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv3.clone(),
            public_metadata: pub3.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT7".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT8".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT6".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT7".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );

        // test bob burning a list, but trying to burn the same token twice
        let burns = vec![
            Burn {
                token_ids: vec!["NFT1".to_string(), "NFT3".to_string()],
                memo: None,
            },
            Burn {
                token_ids: vec!["NFT6".to_string()],
                memo: None,
            },
            Burn {
                token_ids: vec!["NFT6".to_string()],
                memo: None,
            },
            Burn {
                token_ids: vec!["NFT8".to_string()],
                memo: Some("Phew!".to_string()),
            },
        ];
        let execute_msg = ExecuteMsg::BatchBurnNft {
            burns,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        // because the token no longer exists after burning it, it will say you are not
        // authorized if supply is private, and token not found if public
        assert!(error.contains("You are not authorized to perform this action on token NFT6"));

        // set up for batch burn test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv3.clone(),
            public_metadata: pub3.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT7".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT8".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT6".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT7".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );

        // test bob burning a list, but one is not authorized
        let burns = vec![
            Burn {
                token_ids: vec![
                    "NFT1".to_string(),
                    "NFT3".to_string(),
                    "NFT6".to_string(),
                    "NFT2".to_string(),
                ],
                memo: None,
            },
            Burn {
                token_ids: vec!["NFT8".to_string()],
                memo: Some("Phew!".to_string()),
            },
        ];
        let execute_msg = ExecuteMsg::BatchBurnNft {
            burns,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT2"));

        // set up for batch burn test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, false, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: Some(false),
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv3,
            public_metadata: pub3,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT7".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: Some(false),
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT8".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT6".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT7".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );

        // test bob burning NFT1 and 3 from alice with token permission,
        // burning NFT6 as the owner,
        // and burning NFT7 and NFT8 with ALL permission
        let burns = vec![
            Burn {
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Burn {
                token_ids: vec!["NFT3".to_string()],
                memo: None,
            },
            Burn {
                token_ids: vec!["NFT6".to_string(), "NFT7".to_string(), "NFT8".to_string()],
                memo: Some("Phew!".to_string()),
            },
        ];
        let execute_msg = ExecuteMsg::BatchBurnNft {
            burns,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );

        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let tok1_key = 0u32.to_le_bytes();
        let tok2_key = 1u32.to_le_bytes();
        let tok3_key = 2u32.to_le_bytes();
        let tok6_key = 5u32.to_le_bytes();
        let tok7_key = 6u32.to_le_bytes();
        let tok8_key = 6u32.to_le_bytes();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let bob_key = bob_raw.as_slice();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let charlie_key = charlie_raw.as_slice();
        // confirm correct tokens were removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: Option<u32> = may_load(&map2idx, "NFT1".as_bytes()).unwrap();
        assert!(index.is_none());
        let index: Option<u32> = may_load(&map2idx, "NFT2".as_bytes()).unwrap();
        assert!(index.is_some());
        let index: Option<u32> = may_load(&map2idx, "NFT3".as_bytes()).unwrap();
        assert!(index.is_none());
        let index: Option<u32> = may_load(&map2idx, "NFT4".as_bytes()).unwrap();
        assert!(index.is_some());
        let index: Option<u32> = may_load(&map2idx, "NFT5".as_bytes()).unwrap();
        assert!(index.is_some());
        let index: Option<u32> = may_load(&map2idx, "NFT6".as_bytes()).unwrap();
        assert!(index.is_none());
        let index: Option<u32> = may_load(&map2idx, "NFT7".as_bytes()).unwrap();
        assert!(index.is_none());
        let index: Option<u32> = may_load(&map2idx, "NFT8".as_bytes()).unwrap();
        assert!(index.is_none());
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: Option<String> = may_load(&map2id, &0u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        let id: Option<String> = may_load(&map2id, &1u32.to_le_bytes()).unwrap();
        assert!(id.is_some());
        let id: Option<String> = may_load(&map2id, &2u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        let id: Option<String> = may_load(&map2id, &3u32.to_le_bytes()).unwrap();
        assert!(id.is_some());
        let id: Option<String> = may_load(&map2id, &4u32.to_le_bytes()).unwrap();
        assert!(id.is_some());
        let id: Option<String> = may_load(&map2id, &5u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        let id: Option<String> = may_load(&map2id, &6u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        let id: Option<String> = may_load(&map2id, &7u32.to_le_bytes()).unwrap();
        assert!(id.is_none());
        // confirm token infos were deleted from storage
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Option<Token> = json_may_load(&info_store, &tok1_key).unwrap();
        assert!(token.is_none());
        let token: Option<Token> = json_may_load(&info_store, &tok3_key).unwrap();
        assert!(token.is_none());
        let token: Option<Token> = json_may_load(&info_store, &tok6_key).unwrap();
        assert!(token.is_none());
        let token: Option<Token> = json_may_load(&info_store, &tok7_key).unwrap();
        assert!(token.is_none());
        let token: Option<Token> = json_may_load(&info_store, &tok8_key).unwrap();
        assert!(token.is_none());
        // confirm NFT3 metadata has been deleted from storage
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &tok3_key).unwrap();
        assert!(priv_meta.is_none());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Option<Metadata> = may_load(&pub_store, &tok3_key).unwrap();
        assert!(pub_meta.is_none());
        // confirm NFT2 is intact
        let token: Token = json_load(&info_store, &tok2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(
            charlie_tok_perm.expirations[view_meta_idx],
            Some(Expiration::Never)
        );
        assert_eq!(charlie_tok_perm.expirations[transfer_idx], None);
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(token.owner, alice_raw);
        assert!(!token.unwrapped);
        // confirm owner lists are correct
        // alice only owns NFT2
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 1).unwrap());
        // bob owns NFT4 and NFT5
        let inventory = Inventory::new(&deps.storage, bob_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 3).unwrap());
        assert!(inventory.contains(&deps.storage, 4).unwrap());
        // charlie does not own any
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        // confirm AuthLists are correct
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        // alice gave charlie view metadata permission on NFT2
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 1);
        let charlie_auth = alice_list
            .iter()
            .find(|a| a.address == charlie_raw)
            .unwrap();
        assert_eq!(charlie_auth.tokens[view_meta_idx].len(), 1);
        assert!(charlie_auth.tokens[view_meta_idx].contains(&1u32));
        assert!(charlie_auth.tokens[transfer_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        // bob gave charlie view owner and view metadata permission on NFT5
        let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
        assert_eq!(bob_list.len(), 2);
        let charlie_auth = bob_list.iter().find(|a| a.address == charlie_raw).unwrap();
        assert_eq!(charlie_auth.tokens[view_meta_idx].len(), 1);
        assert!(charlie_auth.tokens[view_meta_idx].contains(&4u32));
        assert!(charlie_auth.tokens[transfer_idx].is_empty());
        assert_eq!(charlie_auth.tokens[view_owner_idx].len(), 1);
        assert!(charlie_auth.tokens[view_owner_idx].contains(&4u32));
        // bob gave alice view owner permission on NFT4 and NFT5
        // and transfer permission on NFT5
        let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
        assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
        assert!(alice_auth.tokens[transfer_idx].contains(&4u32));
        assert!(alice_auth.tokens[view_meta_idx].is_empty());
        assert_eq!(alice_auth.tokens[view_owner_idx].len(), 2);
        assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
        assert!(alice_auth.tokens[view_owner_idx].contains(&4u32));
        // charlie has no tokens so should not have any AuthLists
        let charlie_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(charlie_list.is_none());
        // confirm one of the txs
        let (txs, total) = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 3).unwrap();
        assert_eq!(total, 8);
        assert_eq!(txs.len(), 3);
        assert_eq!(txs[0].token_id, "NFT8".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Burn {
                owner: Addr::unchecked("charlie".to_string()),
                burner: Some(Addr::unchecked("bob".to_string())),
            }
        );
        assert_eq!(txs[0].memo, Some("Phew!".to_string()));
        assert_eq!(txs[1].memo, Some("Phew!".to_string()));
        assert_eq!(txs[2].memo, Some("Phew!".to_string()));
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
        assert_eq!(total, 4);
        assert_eq!(txs[0], tx2[0]);
    }

    // test transfer
    #[test]
    fn test_transfer() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("metadata".to_string()),
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test transfer when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        let priv1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: Some("privmetadata".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });
        let pub1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: Some("pubmetadata".to_string()),
                image: Some("puburi".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv1.clone(),
            public_metadata: pub1.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test unauthorized sender (but we'll give him view owner access)
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("MyNFT".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        // test expired token approval
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "bob".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("charlie", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to token MyNFT has expired"));

        // test expired ALL approval
        let execute_msg = ExecuteMsg::ApproveAll {
            operator: "bob".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to all tokens of alice has expired"));

        let tok_key = 0u32.to_le_bytes();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let charlie_key = charlie_raw.as_slice();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let david_key = david_raw.as_slice();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();

        // confirm that transfering to the same address that owns the token does not
        // erase the current permissions
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "alice".to_string(),
            token_id: "MyNFT".to_string(),
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token info is the same
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert_eq!(token.permissions.len(), 2);
        let charlie_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == charlie_raw)
            .unwrap();
        assert_eq!(charlie_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            charlie_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtHeight(10))
        );
        assert_eq!(charlie_tok_perm.expirations[view_owner_idx], None);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[transfer_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert!(token.unwrapped);
        // confirm no transfer tx was logged (latest should be the mint tx)
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(
            txs[0].action,
            TxAction::Mint {
                minter: Addr::unchecked("admin".to_string()),
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        // confirm the owner list is correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's and bob's AuthList were not changed
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 2);
        let charlie_auth = alice_list
            .iter()
            .find(|a| a.address == charlie_raw)
            .unwrap();
        assert_eq!(charlie_auth.tokens[transfer_idx].len(), 1);
        assert!(charlie_auth.tokens[transfer_idx].contains(&0u32));
        assert!(charlie_auth.tokens[view_meta_idx].is_empty());
        assert!(charlie_auth.tokens[view_owner_idx].is_empty());
        let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[view_owner_idx].len(), 1);
        assert!(bob_auth.tokens[view_owner_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[transfer_idx].is_empty());

        // sanity check: operator transfers
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "david".to_string(),
            token_id: "MyNFT".to_string(),
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to david now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, david_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the metadata is intact
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv1.clone().unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &tok_key).unwrap();
        assert_eq!(pub_meta, pub1.clone().unwrap());
        // confirm the tx was logged to all involved parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("bob".to_string())),
                recipient: Addr::unchecked("david".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Xfer it".to_string()));
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        let (tx3, total) = get_txs(&deps.api, &deps.storage, &david_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs, tx2);
        assert_eq!(tx2, tx3);
        // confirm both owner lists are correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        let inventory = Inventory::new(&deps.storage, david_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's and bob's AuthList were removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm david did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, david_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: address with token permission xfers it to itself
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("david", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("charlie", &[]),
            execute_msg,
        );
        // confirm token was not removed from the list
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to charlie now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, charlie_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the metadata is intact
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv1.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &tok_key).unwrap();
        assert_eq!(pub_meta, pub1.unwrap());
        // confirm the tx was logged to all involved parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("david".to_string()),
                sender: Some(Addr::unchecked("charlie".to_string())),
                recipient: Addr::unchecked("charlie".to_string()),
            }
        );
        assert_eq!(txs[0].memo, None);
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &david_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs, tx2);
        // confirm both owner lists are correct
        let inventory = Inventory::new(&deps.storage, david_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's AuthList was removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, david_key).unwrap();
        assert!(auth_list.is_none());
        // confirm charlie did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: owner xfers
        let execute_msg = ExecuteMsg::TransferNft {
            recipient: "alice".to_string(),
            token_id: "MyNFT".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to alice now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the tx was logged to all involved parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("charlie".to_string()),
                sender: None,
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        assert_eq!(txs[0].memo, None);
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 3);
        assert_eq!(txs, tx2);
        // confirm both owner lists are correct
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's AuthList was removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm charlie did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(auth_list.is_none());
    }

    // test batch transfer
    #[test]
    fn test_batch_transfer() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("metadata".to_string()),
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test transfer when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let transfers = vec![Transfer {
            recipient: "bob".to_string(),
            token_ids: vec!["MyNFT".to_string()],
            memo: None,
        }];
        let execute_msg = ExecuteMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let transfers = vec![Transfer {
            recipient: "bob".to_string(),
            token_ids: vec!["MyNFT".to_string()],
            memo: None,
        }];

        // test token not found when supply is public
        let execute_msg = ExecuteMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let tok_key = 0u32.to_le_bytes();
        let tok5_key = 4u32.to_le_bytes();
        let tok3_key = 2u32.to_le_bytes();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let bob_key = bob_raw.as_slice();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let charlie_key = charlie_raw.as_slice();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();

        // set up for batch transfer test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::BatchMintNft {
            mints: vec![
                Mint {
                    token_id: Some("NFT1".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT2".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT3".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT4".to_string()),
                    owner: Some("bob".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT5".to_string()),
                    owner: Some("bob".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT6".to_string()),
                    owner: Some("charlie".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
            ],
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT6".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let transfers = vec![
            Transfer {
                recipient: "charlie".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "alice".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "bob".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "david".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
        ];

        // test transferring the same token among address the sender has ALL permission,
        // but then breaks when it gets to an address he does not have authority for
        let execute_msg = ExecuteMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("david", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));
        // confirm it didn't die until david tried to transfer itaway from bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, bob_raw);

        // set up for batch transfer test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT6".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let transfers = vec![
            Transfer {
                recipient: "charlie".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "alice".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "bob".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
        ];

        // test transferring the same token among address the sender has ALL permission
        // and verify the AuthLists are correct after all the transfers
        let execute_msg = ExecuteMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("david", &[]),
            execute_msg,
        );
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "NFT1".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("NFT1".to_string(), id);
        // confirm token has the correct owner and the permissions were cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, bob_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm transfer txs were logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 10).unwrap();
        assert_eq!(total, 6);
        assert_eq!(txs.len(), 6);
        assert_eq!(
            txs[2].action,
            TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("david".to_string())),
                recipient: Addr::unchecked("charlie".to_string()),
            }
        );
        assert_eq!(
            txs[1].action,
            TxAction::Transfer {
                from: Addr::unchecked("charlie".to_string()),
                sender: Some(Addr::unchecked("david".to_string())),
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("david".to_string())),
                recipient: Addr::unchecked("bob".to_string()),
            }
        );
        // confirm the owner list is correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        assert!(inventory.contains(&deps.storage, 1).unwrap());
        assert!(inventory.contains(&deps.storage, 2).unwrap());
        let inventory = Inventory::new(&deps.storage, bob_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 3);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        assert!(inventory.contains(&deps.storage, 3).unwrap());
        assert!(inventory.contains(&deps.storage, 4).unwrap());
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 5).unwrap());
        // confirm authLists were updated correctly
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 2);
        let david_auth = alice_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[view_meta_idx].len(), 1);
        assert!(david_auth.tokens[view_meta_idx].contains(&2u32));
        assert!(david_auth.tokens[transfer_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());
        let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[view_owner_idx].len(), 1);
        assert!(bob_auth.tokens[view_owner_idx].contains(&2u32));
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 2);
        assert!(bob_auth.tokens[view_meta_idx].contains(&1u32));
        assert!(bob_auth.tokens[view_meta_idx].contains(&2u32));
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
        assert_eq!(bob_list.len(), 1);
        let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
        assert_eq!(alice_auth.tokens[view_owner_idx].len(), 2);
        assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
        assert!(alice_auth.tokens[view_owner_idx].contains(&4u32));
        assert_eq!(alice_auth.tokens[view_meta_idx].len(), 1);
        assert!(alice_auth.tokens[view_meta_idx].contains(&3u32));
        assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
        assert!(alice_auth.tokens[transfer_idx].contains(&3u32));
        let charlie_list: Vec<AuthList> = load(&auth_store, charlie_key).unwrap();
        assert_eq!(charlie_list.len(), 1);
        let bob_auth = charlie_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
        assert!(bob_auth.tokens[view_meta_idx].contains(&5u32));
        assert!(bob_auth.tokens[transfer_idx].is_empty());

        let transfers = vec![
            Transfer {
                recipient: "charlie".to_string(),
                token_ids: vec!["NFT1".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "alice".to_string(),
                token_ids: vec!["NFT5".to_string()],
                memo: None,
            },
            Transfer {
                recipient: "bob".to_string(),
                token_ids: vec!["NFT3".to_string()],
                memo: None,
            },
        ];

        // test bobs trnsfer two of his tokens and one of alice's
        let execute_msg = ExecuteMsg::BatchTransferNft {
            transfers,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm tokens have the correct owner and the permissions were cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, charlie_raw);
        assert!(token.permissions.is_empty());
        let token: Token = json_load(&info_store, &tok3_key).unwrap();
        assert_eq!(token.owner, bob_raw);
        assert!(token.permissions.is_empty());
        let token: Token = json_load(&info_store, &tok5_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.permissions.is_empty());
        // confirm the owner list is correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 1).unwrap());
        assert!(inventory.contains(&deps.storage, 4).unwrap());
        let inventory = Inventory::new(&deps.storage, bob_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 2).unwrap());
        assert!(inventory.contains(&deps.storage, 3).unwrap());
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        assert!(inventory.contains(&deps.storage, 5).unwrap());
        // confirm authLists were updated correctly
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 1);
        let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
        assert!(bob_auth.tokens[view_meta_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].is_empty());
        let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
        assert_eq!(bob_list.len(), 1);
        let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
        assert_eq!(alice_auth.tokens[view_owner_idx].len(), 1);
        assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
        assert_eq!(alice_auth.tokens[view_meta_idx].len(), 1);
        assert!(alice_auth.tokens[view_meta_idx].contains(&3u32));
        assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
        assert!(alice_auth.tokens[transfer_idx].contains(&3u32));
        let charlie_list: Vec<AuthList> = load(&auth_store, charlie_key).unwrap();
        assert_eq!(charlie_list.len(), 1);
        let bob_auth = charlie_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
        assert!(bob_auth.tokens[view_meta_idx].contains(&5u32));
        assert!(bob_auth.tokens[transfer_idx].is_empty());

        // set up for batch transfer test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::BatchMintNft {
            mints: vec![
                Mint {
                    token_id: Some("NFT1".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT2".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT3".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT4".to_string()),
                    owner: Some("bob".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT5".to_string()),
                    owner: Some("bob".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT6".to_string()),
                    owner: Some("charlie".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
            ],
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::BatchTransferNft {
            transfers: vec![
                Transfer {
                    recipient: "charlie".to_string(),
                    token_ids: vec!["NFT2".to_string(), "NFT3".to_string(), "NFT4".to_string()],
                    memo: Some("test memo".to_string()),
                },
                Transfer {
                    recipient: "charlie".to_string(),
                    token_ids: vec!["NFT1".to_string(), "NFT5".to_string()],
                    memo: None,
                },
            ],
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        // confirm charlie's tokens
        let query_msg = QueryMsg::Tokens {
            owner: "charlie".to_string(),
            viewer: None,
            viewing_key: Some("ckey".to_string()),
            start_after: None,
            limit: Some(30),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec![
                    "NFT6".to_string(),
                    "NFT2".to_string(),
                    "NFT3".to_string(),
                    "NFT4".to_string(),
                    "NFT1".to_string(),
                    "NFT5".to_string(),
                ];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
        let xfer4 = Tx {
            tx_id: 8,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT4".to_string(),
            memo: Some("test memo".to_string()),
            action: TxAction::Transfer {
                from: Addr::unchecked("bob".to_string()),
                sender: None,
                recipient: Addr::unchecked("charlie".to_string()),
            },
        };
        let xfer1 = Tx {
            tx_id: 9,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT1".to_string(),
            memo: None,
            action: TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("bob".to_string())),
                recipient: Addr::unchecked("charlie".to_string()),
            },
        };
        let query_msg = QueryMsg::TransactionHistory {
            address: "charlie".to_string(),
            viewing_key: "ckey".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert_eq!(total, 6);
                assert_eq!(txs[1], xfer1);
                assert_eq!(txs[2], xfer4);
            }
            _ => panic!("unexpected"),
        }
        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let query_msg = QueryMsg::Tokens {
            owner: "alice".to_string(),
            viewer: None,
            viewing_key: Some("akey".to_string()),
            start_after: None,
            limit: Some(30),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                assert!(tokens.is_empty());
            }
            _ => panic!("unexpected"),
        }
    }

    // test send
    #[test]
    fn test_send() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("metadata".to_string()),
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test send when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SendNft {
            contract: "bob".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let execute_msg = ExecuteMsg::SendNft {
            contract: "bob".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private
        let execute_msg = ExecuteMsg::SendNft {
            contract: "bob".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        let priv1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: Some("privmetadata".to_string()),
                image: Some("privuri".to_string()),
                ..Extension::default()
            }),
        });
        let pub1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("MyNFT".to_string()),
                description: Some("pubmetadata".to_string()),
                image: Some("puburi".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: priv1.clone(),
            public_metadata: pub1.clone(),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test unauthorized sender (but we'll give him view owner access)
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("MyNFT".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SendNft {
            contract: "bob".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You are not authorized to perform this action on token MyNFT"));

        // test expired token approval
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SendNft {
            contract: "bob".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("charlie", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to token MyNFT has expired"));

        // test expired ALL approval
        let execute_msg = ExecuteMsg::ApproveAll {
            operator: "bob".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SendNft {
            contract: "charlie".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 100,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Access to all tokens of alice has expired"));

        let tok_key = 0u32.to_le_bytes();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let charlie_key = charlie_raw.as_slice();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let david_key = david_raw.as_slice();

        // confirm that sending to the same address that owns the token throws an error
        let execute_msg = ExecuteMsg::SendNft {
            contract: "alice".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: None,
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempting to transfer token ID: MyNFT to the address that already owns it"
        ));

        // sanity check: operator sends
        // msg to go with ReceiveNft
        let send_msg = Some(
            to_binary(&ExecuteMsg::RevokeAll {
                operator: "zoe".to_string(),
                padding: None,
            })
            .unwrap(),
        );
        // register david's ReceiveNft
        let execute_msg = ExecuteMsg::RegisterReceiveNft {
            code_hash: "david code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("david", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SendNft {
            contract: "david".to_string(),
            receiver_info: None,
            token_id: "MyNFT".to_string(),
            msg: send_msg.clone(),
            memo: Some("Xfer it".to_string()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm the receive nft msg was created
        let handle_resp = handle_result.unwrap();
        let messages = handle_resp.messages;
        let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("alice".to_string()),
            token_id: "MyNFT".to_string(),
            msg: send_msg.clone(),
        })
        .unwrap();
        let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
        let msg_fr_al = SubMsg::new(WasmMsg::Execute {
            contract_addr: "david".to_string(),
            code_hash: "david code hash".to_string(),
            msg: Binary(msg_fr_al.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[0], msg_fr_al);
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to david now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, david_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the metadata is intact
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv1.clone().unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &tok_key).unwrap();
        assert_eq!(pub_meta, pub1.clone().unwrap());
        // confirm the tx was logged to all involved parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("bob".to_string())),
                recipient: Addr::unchecked("david".to_string()),
            }
        );
        assert_eq!(txs[0].memo, Some("Xfer it".to_string()));
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &bob_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        let (tx3, total) = get_txs(&deps.api, &deps.storage, &david_raw, 0, 1).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs, tx2);
        assert_eq!(tx2, tx3);
        // confirm both owner lists are correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        let inventory = Inventory::new(&deps.storage, david_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's and bob's AuthList were removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm david did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, david_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: address with token permission xfers it to itself and specifies its
        // code hash and that it implements BatchReceiveNft in the SendNft msg
        let execute_msg = ExecuteMsg::Approve {
            spender: "charlie".to_string(),
            token_id: "MyNFT".to_string(),
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("david", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SendNft {
            contract: "charlie".to_string(),
            receiver_info: Some(ReceiverInfo {
                recipient_code_hash: "supplied in the send".to_string(),
                also_implements_batch_receive_nft: Some(true),
            }),
            token_id: "MyNFT".to_string(),
            msg: send_msg.clone(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            Env {
                block: BlockInfo {
                    height: 1,
                    time: Timestamp::from_seconds(100),
                    chain_id: "cosmos-testnet-14002".to_string(),
                    random: None,
                },
                transaction: None,
                contract: cosmwasm_std::ContractInfo {
                    address: Addr::unchecked(MOCK_CONTRACT_ADDR),
                    code_hash: "".to_string(),
                },
            },
            mock_info("charlie", &[]),
            execute_msg,
        );
        // confirm the batch receive nft msg was created
        let handle_resp = handle_result.unwrap();
        let messages = handle_resp.messages;
        let mut msg_fr_dv = to_binary(&Snip721ReceiveMsg::BatchReceiveNft {
            sender: Addr::unchecked("charlie".to_string()),
            from: Addr::unchecked("david".to_string()),
            token_ids: vec!["MyNFT".to_string()],
            msg: send_msg.clone(),
        })
        .unwrap();
        let msg_fr_dv = space_pad(&mut msg_fr_dv.0, 256usize);
        let msg_fr_dv = SubMsg::new(WasmMsg::Execute {
            contract_addr: "charlie".to_string(),
            code_hash: "supplied in the send".to_string(),
            msg: Binary(msg_fr_dv.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[0], msg_fr_dv);
        // confirm token was not removed from the list
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to charlie now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, charlie_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the metadata is intact
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Metadata = load(&priv_store, &tok_key).unwrap();
        assert_eq!(priv_meta, priv1.unwrap());
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &tok_key).unwrap();
        assert_eq!(pub_meta, pub1.unwrap());
        // confirm the tx was logged to all involved parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 10).unwrap();
        assert_eq!(total, 1);
        assert_eq!(txs.len(), 1);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("david".to_string()),
                sender: Some(Addr::unchecked("charlie".to_string())),
                recipient: Addr::unchecked("charlie".to_string()),
            }
        );
        assert_eq!(txs[0].memo, None);
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &david_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs, tx2);
        // confirm both owner lists are correct
        let inventory = Inventory::new(&deps.storage, david_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's AuthList was removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, david_key).unwrap();
        assert!(auth_list.is_none());
        // confirm charlie did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(auth_list.is_none());

        // sanity check: owner sends and specifies a code hash in the send
        let execute_msg = ExecuteMsg::SendNft {
            contract: "alice".to_string(),
            receiver_info: Some(ReceiverInfo {
                recipient_code_hash: "supplied in the send".to_string(),
                also_implements_batch_receive_nft: None,
            }),
            token_id: "MyNFT".to_string(),
            msg: send_msg.clone(),
            memo: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        // confirm the receive nft msg was created
        let handle_resp = handle_result.unwrap();
        let messages = handle_resp.messages;
        let mut msg_fr_ch = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("charlie".to_string()),
            token_id: "MyNFT".to_string(),
            msg: send_msg,
        })
        .unwrap();
        let msg_fr_ch = space_pad(&mut msg_fr_ch.0, 256usize);
        let msg_fr_ch = SubMsg::new(WasmMsg::Execute {
            contract_addr: "alice".to_string(),
            code_hash: "supplied in the send".to_string(),
            msg: Binary(msg_fr_ch.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[0], msg_fr_ch);
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "MyNFT".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("MyNFT".to_string(), id);
        // confirm token belongs to alice now and permissions have been cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm the tx was logged to all involved parties
        let (txs, total) = get_txs(&deps.api, &deps.storage, &charlie_raw, 0, 1).unwrap();
        assert_eq!(total, 2);
        assert_eq!(txs[0].token_id, "MyNFT".to_string());
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("charlie".to_string()),
                sender: None,
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        assert_eq!(txs[0].memo, None);
        let (tx2, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 1).unwrap();
        assert_eq!(total, 3);
        assert_eq!(txs, tx2);
        // confirm both owner lists are correct
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 0);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        // confirm charlie's AuthList was removed because the only token was xferred
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
        // confirm charlie did not inherit any AuthLists from the xfer
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, charlie_key).unwrap();
        assert!(auth_list.is_none());
    }

    // test batch send
    #[test]
    fn test_batch_send() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("MyNFT".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("MyNFT".to_string()),
                    description: Some("metadata".to_string()),
                    image: Some("uri".to_string()),
                    ..Extension::default()
                }),
            }),
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint it baby!".to_string()),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test send when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let sends = vec![Send {
            contract: "bob".to_string(),
            receiver_info: None,
            token_ids: vec!["MyNFT".to_string()],
            msg: None,
            memo: None,
        }];
        let execute_msg = ExecuteMsg::BatchSendNft {
            sends,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::Normal,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let sends = vec![Send {
            contract: "bob".to_string(),
            receiver_info: None,
            token_ids: vec!["MyNFT".to_string()],
            msg: None,
            memo: None,
        }];

        // test token not found when supply is public
        let execute_msg = ExecuteMsg::BatchSendNft {
            sends,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: MyNFT not found"));

        let tok_key = 0u32.to_le_bytes();
        let tok5_key = 4u32.to_le_bytes();
        let tok3_key = 2u32.to_le_bytes();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let bob_key = bob_raw.as_slice();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let charlie_key = charlie_raw.as_slice();
        let david_raw = deps.api.addr_canonicalize("david").unwrap();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();

        // set up for batch send test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some("bob".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some("charlie".to_string()),
            private_metadata: None,
            public_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT4".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "alice".to_string(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT6".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "david".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::RegisterReceiveNft {
            code_hash: "charlie code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        // msg to go with ReceiveNft
        let send_msg = Some(
            to_binary(&ExecuteMsg::RevokeAll {
                operator: "zoe".to_string(),
                padding: None,
            })
            .unwrap(),
        );
        let sends = vec![
            Send {
                contract: "charlie".to_string(),
                receiver_info: None,
                token_ids: vec!["NFT1".to_string()],
                msg: send_msg.clone(),
                memo: None,
            },
            Send {
                contract: "alice".to_string(),
                receiver_info: None,
                token_ids: vec!["NFT1".to_string()],
                msg: send_msg.clone(),
                memo: None,
            },
            Send {
                contract: "bob".to_string(),
                receiver_info: Some(ReceiverInfo {
                    recipient_code_hash: "supplied in the send".to_string(),
                    also_implements_batch_receive_nft: None,
                }),
                token_ids: vec!["NFT1".to_string()],
                msg: send_msg.clone(),
                memo: None,
            },
        ];

        // test sending the same token among address the sender has ALL permission
        // and verify the AuthLists are correct after all the transfers
        let execute_msg = ExecuteMsg::BatchSendNft {
            sends,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("david", &[]),
            execute_msg,
        );
        // confirm the receive nft msgs were created
        let handle_resp = handle_result.unwrap();
        let messages = handle_resp.messages;
        let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("alice".to_string()),
            token_id: "NFT1".to_string(),
            msg: send_msg.clone(),
        })
        .unwrap();
        let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
        let msg_fr_al = SubMsg::new(WasmMsg::Execute {
            contract_addr: "charlie".to_string(),
            code_hash: "charlie code hash".to_string(),
            msg: Binary(msg_fr_al.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[0], msg_fr_al);
        assert_eq!(messages.len(), 2);
        let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("alice".to_string()),
            token_id: "NFT1".to_string(),
            msg: send_msg.clone(),
        })
        .unwrap();
        let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
        let msg_fr_al = SubMsg::new(WasmMsg::Execute {
            contract_addr: "bob".to_string(),
            code_hash: "supplied in the send".to_string(),
            msg: Binary(msg_fr_al.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[1], msg_fr_al);
        // confirm token was not removed from the maps
        let map2idx = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_INDEX);
        let index: u32 = load(&map2idx, "NFT1".as_bytes()).unwrap();
        let token_key = index.to_le_bytes();
        let map2id = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_MAP_TO_ID);
        let id: String = load(&map2id, &token_key).unwrap();
        assert_eq!("NFT1".to_string(), id);
        // confirm token has the correct owner and the permissions were cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, bob_raw);
        assert!(token.permissions.is_empty());
        assert!(token.unwrapped);
        // confirm transfer txs were logged
        let (txs, total) = get_txs(&deps.api, &deps.storage, &alice_raw, 0, 10).unwrap();
        assert_eq!(total, 6);
        assert_eq!(txs.len(), 6);
        assert_eq!(
            txs[2].action,
            TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("david".to_string())),
                recipient: Addr::unchecked("charlie".to_string()),
            }
        );
        assert_eq!(
            txs[1].action,
            TxAction::Transfer {
                from: Addr::unchecked("charlie".to_string()),
                sender: Some(Addr::unchecked("david".to_string())),
                recipient: Addr::unchecked("alice".to_string()),
            }
        );
        assert_eq!(
            txs[0].action,
            TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("david".to_string())),
                recipient: Addr::unchecked("bob".to_string()),
            }
        );
        // confirm the owner list is correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(!inventory.contains(&deps.storage, 0).unwrap());
        assert!(inventory.contains(&deps.storage, 1).unwrap());
        assert!(inventory.contains(&deps.storage, 2).unwrap());
        let inventory = Inventory::new(&deps.storage, bob_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 3);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        assert!(inventory.contains(&deps.storage, 3).unwrap());
        assert!(inventory.contains(&deps.storage, 4).unwrap());
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 1);
        assert!(inventory.contains(&deps.storage, 5).unwrap());
        // confirm authLists were updated correctly
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 2);
        let david_auth = alice_list.iter().find(|a| a.address == david_raw).unwrap();
        assert_eq!(david_auth.tokens[view_meta_idx].len(), 1);
        assert!(david_auth.tokens[view_meta_idx].contains(&2u32));
        assert!(david_auth.tokens[transfer_idx].is_empty());
        assert!(david_auth.tokens[view_owner_idx].is_empty());
        let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[view_owner_idx].len(), 1);
        assert!(bob_auth.tokens[view_owner_idx].contains(&2u32));
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 2);
        assert!(bob_auth.tokens[view_meta_idx].contains(&1u32));
        assert!(bob_auth.tokens[view_meta_idx].contains(&2u32));
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
        assert_eq!(bob_list.len(), 1);
        let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
        assert_eq!(alice_auth.tokens[view_owner_idx].len(), 2);
        assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
        assert!(alice_auth.tokens[view_owner_idx].contains(&4u32));
        assert_eq!(alice_auth.tokens[view_meta_idx].len(), 1);
        assert!(alice_auth.tokens[view_meta_idx].contains(&3u32));
        assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
        assert!(alice_auth.tokens[transfer_idx].contains(&3u32));
        let charlie_list: Vec<AuthList> = load(&auth_store, charlie_key).unwrap();
        assert_eq!(charlie_list.len(), 1);
        let bob_auth = charlie_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
        assert!(bob_auth.tokens[view_meta_idx].contains(&5u32));
        assert!(bob_auth.tokens[transfer_idx].is_empty());

        let sends = vec![
            Send {
                contract: "charlie".to_string(),
                receiver_info: None,
                token_ids: vec!["NFT1".to_string()],
                msg: send_msg.clone(),
                memo: None,
            },
            Send {
                contract: "alice".to_string(),
                receiver_info: None,
                token_ids: vec!["NFT5".to_string()],
                msg: send_msg.clone(),
                memo: None,
            },
            Send {
                contract: "bob".to_string(),
                receiver_info: Some(ReceiverInfo {
                    recipient_code_hash: "supplied in the send".to_string(),
                    also_implements_batch_receive_nft: Some(true),
                }),
                token_ids: vec!["NFT3".to_string()],
                msg: send_msg.clone(),
                memo: None,
            },
        ];

        // test bob transfers two of his tokens and one of alice's
        let execute_msg = ExecuteMsg::BatchSendNft {
            sends,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        // confirm the receive nft msgs were created
        let handle_resp = handle_result.unwrap();
        let messages = handle_resp.messages;
        let mut msg_fr_b = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("bob".to_string()),
            token_id: "NFT1".to_string(),
            msg: send_msg.clone(),
        })
        .unwrap();
        let msg_fr_b = space_pad(&mut msg_fr_b.0, 256usize);
        let msg_fr_b = SubMsg::new(WasmMsg::Execute {
            contract_addr: "charlie".to_string(),
            code_hash: "charlie code hash".to_string(),
            msg: Binary(msg_fr_b.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[0], msg_fr_b);
        assert_eq!(messages.len(), 2);
        let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::BatchReceiveNft {
            sender: Addr::unchecked("bob".to_string()),
            from: Addr::unchecked("alice".to_string()),
            token_ids: vec!["NFT3".to_string()],
            msg: send_msg,
        })
        .unwrap();
        let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
        let msg_fr_al = SubMsg::new(WasmMsg::Execute {
            contract_addr: "bob".to_string(),
            code_hash: "supplied in the send".to_string(),
            msg: Binary(msg_fr_al.to_vec()),
            funds: vec![],
        });
        assert_eq!(messages[1], msg_fr_al);
        // confirm tokens have the correct owner and the permissions were cleared
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &tok_key).unwrap();
        assert_eq!(token.owner, charlie_raw);
        assert!(token.permissions.is_empty());
        let token: Token = json_load(&info_store, &tok3_key).unwrap();
        assert_eq!(token.owner, bob_raw);
        assert!(token.permissions.is_empty());
        let token: Token = json_load(&info_store, &tok5_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.permissions.is_empty());
        // confirm the owner list is correct
        let inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 1).unwrap());
        assert!(inventory.contains(&deps.storage, 4).unwrap());
        let inventory = Inventory::new(&deps.storage, bob_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 2).unwrap());
        assert!(inventory.contains(&deps.storage, 3).unwrap());
        let inventory = Inventory::new(&deps.storage, charlie_raw.clone()).unwrap();
        assert_eq!(inventory.cnt, 2);
        assert!(inventory.contains(&deps.storage, 0).unwrap());
        assert!(inventory.contains(&deps.storage, 5).unwrap());
        // confirm authLists were updated correctly
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let alice_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(alice_list.len(), 1);
        let bob_auth = alice_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
        assert!(bob_auth.tokens[view_meta_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].is_empty());
        let bob_list: Vec<AuthList> = load(&auth_store, bob_key).unwrap();
        assert_eq!(bob_list.len(), 1);
        let alice_auth = bob_list.iter().find(|a| a.address == alice_raw).unwrap();
        assert_eq!(alice_auth.tokens[view_owner_idx].len(), 1);
        assert!(alice_auth.tokens[view_owner_idx].contains(&3u32));
        assert_eq!(alice_auth.tokens[view_meta_idx].len(), 1);
        assert!(alice_auth.tokens[view_meta_idx].contains(&3u32));
        assert_eq!(alice_auth.tokens[transfer_idx].len(), 1);
        assert!(alice_auth.tokens[transfer_idx].contains(&3u32));
        let charlie_list: Vec<AuthList> = load(&auth_store, charlie_key).unwrap();
        assert_eq!(charlie_list.len(), 1);
        let bob_auth = charlie_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        assert_eq!(bob_auth.tokens[view_meta_idx].len(), 1);
        assert!(bob_auth.tokens[view_meta_idx].contains(&5u32));
        assert!(bob_auth.tokens[transfer_idx].is_empty());

        // set up for batch send test
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::BatchMintNft {
            mints: vec![
                Mint {
                    token_id: Some("NFT1".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT2".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT3".to_string()),
                    owner: Some("alice".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT4".to_string()),
                    owner: Some("bob".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT5".to_string()),
                    owner: Some("bob".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
                Mint {
                    token_id: Some("NFT6".to_string()),
                    owner: Some("charlie".to_string()),
                    private_metadata: None,
                    public_metadata: None,
                    royalty_info: None,
                    serial_number: None,
                    transferable: None,
                    memo: None,
                },
            ],
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::RegisterReceiveNft {
            code_hash: "alice code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::RegisterReceiveNft {
            code_hash: "charlie code hash".to_string(),
            also_implements_batch_receive_nft: Some(true),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let send_msg = Some(
            to_binary(&ExecuteMsg::RevokeAll {
                operator: "zoe".to_string(),
                padding: None,
            })
            .unwrap(),
        );
        let execute_msg = ExecuteMsg::BatchSendNft {
            sends: vec![
                Send {
                    contract: "charlie".to_string(),
                    receiver_info: None,
                    token_ids: vec!["NFT2".to_string(), "NFT3".to_string(), "NFT4".to_string()],
                    msg: send_msg.clone(),
                    memo: Some("test memo".to_string()),
                },
                Send {
                    contract: "alice".to_string(),
                    receiver_info: None,
                    token_ids: vec!["NFT3".to_string(), "NFT4".to_string(), "NFT6".to_string()],
                    msg: None,
                    memo: None,
                },
            ],
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let handle_resp = handle_result.unwrap();
        let messages = handle_resp.messages;
        let mut msg_fr_al = to_binary(&Snip721ReceiveMsg::BatchReceiveNft {
            sender: Addr::unchecked("bob".to_string()),
            from: Addr::unchecked("alice".to_string()),
            token_ids: vec!["NFT2".to_string(), "NFT3".to_string()],
            msg: send_msg.clone(),
        })
        .unwrap();
        let msg_fr_al = space_pad(&mut msg_fr_al.0, 256usize);
        let msg_fr_al = SubMsg::new(WasmMsg::Execute {
            contract_addr: "charlie".to_string(),
            code_hash: "charlie code hash".to_string(),
            msg: Binary(msg_fr_al.to_vec()),
            funds: vec![],
        });
        let mut msf_fr_b = to_binary(&Snip721ReceiveMsg::BatchReceiveNft {
            sender: Addr::unchecked("bob".to_string()),
            from: Addr::unchecked("bob".to_string()),
            token_ids: vec!["NFT4".to_string()],
            msg: send_msg,
        })
        .unwrap();
        let msg_fr_b = space_pad(&mut msf_fr_b.0, 256usize);
        let msg_fr_b = SubMsg::new(WasmMsg::Execute {
            contract_addr: "charlie".to_string(),
            code_hash: "charlie code hash".to_string(),
            msg: Binary(msg_fr_b.to_vec()),
            funds: vec![],
        });
        let mut msg_fr_c3 = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("charlie".to_string()),
            token_id: "NFT3".to_string(),
            msg: None,
        })
        .unwrap();
        let msg_fr_c3 = space_pad(&mut msg_fr_c3.0, 256usize);
        let msg_fr_c3 = SubMsg::new(WasmMsg::Execute {
            contract_addr: "alice".to_string(),
            code_hash: "alice code hash".to_string(),
            msg: Binary(msg_fr_c3.to_vec()),
            funds: vec![],
        });
        let mut msg_fr_c4 = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("charlie".to_string()),
            token_id: "NFT4".to_string(),
            msg: None,
        })
        .unwrap();
        let msg_fr_c4 = space_pad(&mut msg_fr_c4.0, 256usize);
        let msg_fr_c4 = SubMsg::new(WasmMsg::Execute {
            contract_addr: "alice".to_string(),
            code_hash: "alice code hash".to_string(),
            msg: Binary(msg_fr_c4.to_vec()),
            funds: vec![],
        });
        let mut msg_fr_c6 = to_binary(&Snip721ReceiveMsg::ReceiveNft {
            sender: Addr::unchecked("charlie".to_string()),
            token_id: "NFT6".to_string(),
            msg: None,
        })
        .unwrap();
        let msg_fr_c6 = space_pad(&mut msg_fr_c6.0, 256usize);
        let msg_fr_c6 = SubMsg::new(WasmMsg::Execute {
            contract_addr: "alice".to_string(),
            code_hash: "alice code hash".to_string(),
            msg: Binary(msg_fr_c6.to_vec()),
            funds: vec![],
        });
        let expected_msgs = vec![msg_fr_al, msg_fr_b, msg_fr_c3, msg_fr_c4, msg_fr_c6];
        assert_eq!(messages, expected_msgs);
        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("charlie", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm alice's tokens
        let query_msg = QueryMsg::Tokens {
            owner: "alice".to_string(),
            viewer: None,
            viewing_key: Some("akey".to_string()),
            start_after: None,
            limit: Some(30),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec![
                    "NFT1".to_string(),
                    "NFT3".to_string(),
                    "NFT4".to_string(),
                    "NFT6".to_string(),
                ];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
        let xfer6 = Tx {
            tx_id: 11,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT6".to_string(),
            memo: None,
            action: TxAction::Transfer {
                from: Addr::unchecked("charlie".to_string()),
                sender: Some(Addr::unchecked("bob".to_string())),
                recipient: Addr::unchecked("alice".to_string()),
            },
        };
        let xfer3 = Tx {
            tx_id: 7,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT3".to_string(),
            memo: Some("test memo".to_string()),
            action: TxAction::Transfer {
                from: Addr::unchecked("alice".to_string()),
                sender: Some(Addr::unchecked("bob".to_string())),
                recipient: Addr::unchecked("charlie".to_string()),
            },
        };
        let query_msg = QueryMsg::TransactionHistory {
            address: "alice".to_string(),
            viewing_key: "akey".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert_eq!(total, 8);
                assert_eq!(txs[3], xfer3);
                assert_eq!(txs[0], xfer6);
            }
            _ => panic!("unexpected"),
        }
        let query_msg = QueryMsg::Tokens {
            owner: "charlie".to_string(),
            viewer: None,
            viewing_key: Some("ckey".to_string()),
            start_after: None,
            limit: Some(30),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT2".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
    }

    // test register receive_nft
    #[test]
    fn test_register_receive_nft() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test register when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::RegisterReceiveNft {
            code_hash: "alice code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still register when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // sanity check
        let execute_msg = ExecuteMsg::RegisterReceiveNft {
            code_hash: "alice code hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_RECEIVERS);
        let hash: String = load(
            &store,
            deps.api.addr_canonicalize("alice").unwrap().as_slice(),
        )
        .unwrap();
        assert_eq!(&hash, "alice code hash");
    }

    // test create viewing key
    #[test]
    fn test_create_viewing_key() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test creating a key when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::CreateViewingKey {
            entropy: "blah".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still create a key when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::CreateViewingKey {
            entropy: "blah".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        assert!(
            handle_result.is_ok(),
            "handle() failed: {}",
            handle_result.err().unwrap()
        );
        let answer: ExecuteAnswer = from_binary(&handle_result.unwrap().data.unwrap()).unwrap();

        let key_str = match answer {
            ExecuteAnswer::ViewingKey { key } => key,
            _ => panic!("NOPE"),
        };
        assert!(ViewingKey::check(&deps.storage, "alice", &key_str).is_ok());
    }

    // test set viewing key
    #[test]
    fn test_set_viewing_key() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test setting a key when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "blah".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still set a key when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "blah".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        assert!(ViewingKey::check(&deps.storage, "alice", "blah").is_ok());
    }

    // test add minters
    #[test]
    fn test_add_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test adding minters when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let minters = vec![
            "alice".to_string(),
            "bob".to_string(),
            "bob".to_string(),
            "alice".to_string(),
        ];
        let execute_msg = ExecuteMsg::AddMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still add minters when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test non admin trying to add minters
        let execute_msg = ExecuteMsg::AddMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let admin_raw = deps.api.addr_canonicalize("admin").unwrap();
        // verify the minters we will add are not already in the list
        assert!(!cur_minter.contains(&alice_raw));
        assert!(!cur_minter.contains(&bob_raw));
        let execute_msg = ExecuteMsg::AddMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify the new minters were added
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 3);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's try an empty list to see if it breaks
        let minters = vec![];
        let execute_msg = ExecuteMsg::AddMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify it's the same list
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 3);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&admin_raw));
    }

    // test remove minters
    #[test]
    fn test_remove_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test removing minters when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let minters = vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
            "bob".to_string(),
        ];
        let execute_msg = ExecuteMsg::RemoveMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still remove minters when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test non admin trying to remove minters
        let execute_msg = ExecuteMsg::RemoveMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let admin_raw = deps.api.addr_canonicalize("admin").unwrap();
        let execute_msg = ExecuteMsg::AddMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify the new minters were added
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 4);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&charlie_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's give it an empty list to see if it breaks
        let minters = vec![];
        let execute_msg = ExecuteMsg::RemoveMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify it is the same list
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 4);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&charlie_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's throw some repeats to see if it breaks
        let minters = vec![
            "alice".to_string(),
            "bob".to_string(),
            "alice".to_string(),
            "charlie".to_string(),
        ];
        let execute_msg = ExecuteMsg::RemoveMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify the minters were removed
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 1);
        assert!(!cur_minter.contains(&alice_raw));
        assert!(!cur_minter.contains(&bob_raw));
        assert!(!cur_minter.contains(&charlie_raw));
        assert!(cur_minter.contains(&admin_raw));

        // let's remove the last one
        let execute_msg = ExecuteMsg::RemoveMinters {
            minters: vec!["admin".to_string()],
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify the minters were removed
        let cur_minter: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY).unwrap();
        assert!(cur_minter.is_none());
    }

    // test set minters
    #[test]
    fn test_set_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test setting minters when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let minters = vec![
            "alice".to_string(),
            "bob".to_string(),
            "charlie".to_string(),
            "bob".to_string(),
            "alice".to_string(),
        ];
        let execute_msg = ExecuteMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still set minters when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test non admin trying to set minters
        let execute_msg = ExecuteMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let execute_msg = ExecuteMsg::SetMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify the new minters were added
        let cur_minter: Vec<CanonicalAddr> = load(&deps.storage, MINTERS_KEY).unwrap();
        assert_eq!(cur_minter.len(), 3);
        assert!(cur_minter.contains(&alice_raw));
        assert!(cur_minter.contains(&bob_raw));
        assert!(cur_minter.contains(&charlie_raw));
        // let's try an empty list
        let minters = vec![];
        let execute_msg = ExecuteMsg::SetMinters {
            minters,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify the minters were removed
        let cur_minter: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY).unwrap();
        assert!(cur_minter.is_none());
    }

    // test change admin
    #[test]
    fn test_change_admin() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test changing admin when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::ChangeAdmin {
            address: "alice".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still change admin when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test non admin trying to change admin
        let execute_msg = ExecuteMsg::ChangeAdmin {
            address: "alice".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let admin_raw = deps.api.addr_canonicalize("admin").unwrap();
        // verify admin is the current admin
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.admin, admin_raw);
        // change it to alice
        let execute_msg = ExecuteMsg::ChangeAdmin {
            address: "alice".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify admin was changed
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.admin, alice_raw);
    }

    // test set contract status
    #[test]
    fn test_set_contract_status() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test non admin trying to change status
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(
            error.contains("This is an admin command and can only be run from the admin address")
        );

        // sanity check
        // verify current status is normal
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::Normal.to_u8());
        // change it to StopAll
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        // verify status was changed
        let config: Config = load(&deps.storage, CONFIG_KEY).unwrap();
        assert_eq!(config.status, ContractStatus::StopAll.to_u8());
    }

    // test approve_all from the cw721 spec
    #[test]
    fn test_cw721_approve_all() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        ); // test burn when status prevents it
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test trying to ApproveAll when status does not allow
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::ApproveAll {
            operator: "bob".to_string(),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));
        // setting approval is ok even during StopTransactions status
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let nft3_key = 2u32.to_le_bytes();

        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );

        // confirm bob has transfer token permissions but not transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permission has bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT2 permission has bob
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT3 permission has bob
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm AuthLists has bob
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 3);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // test that ApproveAll will remove all the token permissions
        let execute_msg = ExecuteMsg::ApproveAll {
            operator: "bob".to_string(),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm bob has transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_oper_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm bob's NFT1 permission is gone
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm bob's NFT2 permission is gone
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm bob's NFT3 permission is gone
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists no longer have bob
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());
    }

    // test revoke_all from the cw721 spec
    #[test]
    fn test_cw721_revoke_all() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        ); // test burn when status prevents it
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test trying to RevokeAll when status does not allow
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::RevokeAll {
            operator: "bob".to_string(),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));
        // setting approval is ok even during StopTransactions status
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let nft3_key = 2u32.to_le_bytes();

        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );

        // confirm bob has transfer token permissions but not transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm NFT1 permission has bob
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT2 permission has bob
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm NFT3 permission has bob
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // confirm AuthLists has bob
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 3);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&1u32));
        assert!(bob_auth.tokens[transfer_idx].contains(&2u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());

        // test that RevokeAll will remove all the token permissions
        let execute_msg = ExecuteMsg::RevokeAll {
            operator: "bob".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm bob does not have transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        // confirm bob's NFT1 permission is gone
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm bob's NFT2 permission is gone
        let token: Token = json_load(&info_store, &nft2_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm bob's NFT3 permission is gone
        let token: Token = json_load(&info_store, &nft3_key).unwrap();
        assert!(token.permissions.is_empty());
        // confirm AuthLists no longer have bob
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Option<Vec<AuthList>> = may_load(&auth_store, alice_key).unwrap();
        assert!(auth_list.is_none());

        // grant bob transfer all permission to test if revoke all removes it
        let execute_msg = ExecuteMsg::ApproveAll {
            operator: "bob".to_string(),
            expires: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm bob has transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(
            bob_oper_perm.expirations[transfer_idx],
            Some(Expiration::Never)
        );
        // now get rid of it
        let execute_msg = ExecuteMsg::RevokeAll {
            operator: "bob".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm bob no longer has transfer all permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::Never)
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
    }

    // test making ownership private
    #[test]
    fn test_make_ownership_private() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test setting privacy when status prevents it
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MakeOwnershipPrivate { padding: None };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));

        // you can still set privacy when transactions are stopped
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // sanity check when contract default is private
        let execute_msg = ExecuteMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_OWNER_PRIV);
        let owner_priv: Option<bool> = may_load(&store, alice_key).unwrap();
        assert!(owner_priv.is_none());

        // test when contract default is public
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_OWNER_PRIV);
        let owner_priv: bool = load(&store, alice_key).unwrap();
        assert!(!owner_priv);
    }

    // test owner setting global approvals
    #[test]
    fn test_set_global_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is public
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token does not exist when supply is private
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        let pub1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My1".to_string()),
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub1.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test trying to set approval when status does not allow
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopAll,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The contract admin has temporarily disabled this action"));
        // setting approval is ok even during StopTransactions status
        let execute_msg = ExecuteMsg::SetContractStatus {
            level: ContractStatus::StopTransactions,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // only allow the owner to use SetGlobalApproval
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("You do not own token NFT1"));

        // try approving a token without specifying which token
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // try revoking a token approval without specifying which token
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::RevokeToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains(
            "Attempted to grant/revoke permission for a token, but did not specify a token ID"
        ));

        // sanity check
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let global_raw = CanonicalAddr(Binary::from(b"public"));
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let alice_key = alice_raw.as_slice();
        let view_owner_idx = PermissionType::ViewOwner.to_usize();
        let view_meta_idx = PermissionType::ViewMetadata.to_usize();
        let transfer_idx = PermissionType::Transfer.to_usize();
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 1);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions and that the token data did not get modified
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let nft1_key = 0u32.to_le_bytes();
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.owner, alice_raw);
        assert!(token.unwrapped);
        let pub_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PUB_META);
        let pub_meta: Metadata = load(&pub_store, &nft1_key).unwrap();
        assert_eq!(pub_meta, pub1.unwrap());
        let priv_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_PRIV_META);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &nft1_key).unwrap();
        assert!(priv_meta.is_none());
        assert_eq!(token.permissions.len(), 1);
        let global_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == global_raw)
            .unwrap();
        assert_eq!(
            global_tok_perm.expirations[view_meta_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_tok_perm.expirations[transfer_idx], None);
        assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has public with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
        assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
        assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
        assert!(global_auth.tokens[transfer_idx].is_empty());
        assert!(global_auth.tokens[view_owner_idx].is_empty());

        // bob approvals to make sure whitelisted addresses don't break
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(
            global_tok_perm.expirations[view_meta_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_tok_perm.expirations[transfer_idx], None);
        assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
        assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
        assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
        assert!(global_auth.tokens[transfer_idx].is_empty());
        assert!(global_auth.tokens[view_owner_idx].is_empty());

        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 2);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        assert_eq!(
            global_tok_perm.expirations[view_meta_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_tok_perm.expirations[transfer_idx], None);
        assert_eq!(global_tok_perm.expirations[view_owner_idx], None);
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 2);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let global_auth = auth_list.iter().find(|a| a.address == global_raw).unwrap();
        assert_eq!(global_auth.tokens[view_meta_idx].len(), 1);
        assert!(global_auth.tokens[view_meta_idx].contains(&0u32));
        assert!(global_auth.tokens[transfer_idx].is_empty());
        assert!(global_auth.tokens[view_owner_idx].is_empty());

        // test revoking global approval
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::None),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        // confirm ALL permission
        let all_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_ALL_PERMISSIONS);
        let all_perm: Vec<Permission> = json_load(&all_store, alice_key).unwrap();
        assert_eq!(all_perm.len(), 2);
        let bob_oper_perm = all_perm.iter().find(|p| p.address == bob_raw).unwrap();
        assert_eq!(
            bob_oper_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_oper_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_oper_perm.expirations[transfer_idx], None);
        let global_perm = all_perm.iter().find(|p| p.address == global_raw).unwrap();
        assert_eq!(
            global_perm.expirations[view_owner_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(global_perm.expirations[view_meta_idx], None);
        assert_eq!(global_perm.expirations[transfer_idx], None);
        // confirm NFT1 permissions
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token: Token = json_load(&info_store, &nft1_key).unwrap();
        assert_eq!(token.permissions.len(), 1);
        let bob_tok_perm = token
            .permissions
            .iter()
            .find(|p| p.address == bob_raw)
            .unwrap();
        assert_eq!(
            bob_tok_perm.expirations[transfer_idx],
            Some(Expiration::AtTime(1000000))
        );
        assert_eq!(bob_tok_perm.expirations[view_meta_idx], None);
        assert_eq!(bob_tok_perm.expirations[view_owner_idx], None);
        let global_tok_perm = token.permissions.iter().find(|p| p.address == global_raw);
        assert!(global_tok_perm.is_none());
        // confirm AuthLists has bob with NFT1 permission
        let auth_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_AUTHLIST);
        let auth_list: Vec<AuthList> = load(&auth_store, alice_key).unwrap();
        assert_eq!(auth_list.len(), 1);
        let bob_auth = auth_list.iter().find(|a| a.address == bob_raw).unwrap();
        assert_eq!(bob_auth.tokens[transfer_idx].len(), 1);
        assert!(bob_auth.tokens[transfer_idx].contains(&0u32));
        assert!(bob_auth.tokens[view_meta_idx].is_empty());
        assert!(bob_auth.tokens[view_owner_idx].is_empty());
        let global_auth = auth_list.iter().find(|a| a.address == global_raw);
        assert!(global_auth.is_none());
    }

    // test permissioning works
    #[test]
    fn test_check_permission() {
        let (init_result, mut deps) =
            init_helper_with_config(true, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(1),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let alice_raw = deps.api.addr_canonicalize("alice").unwrap();
        let bob_raw = deps.api.addr_canonicalize("bob").unwrap();
        let charlie_raw = deps.api.addr_canonicalize("charlie").unwrap();
        let nft1_key = 0u32.to_le_bytes();
        let nft2_key = 1u32.to_le_bytes();
        let pub1 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My1".to_string()),
                description: Some("Pub 1".to_string()),
                image: Some("URI 1".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub1.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let pub2 = Some(Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("My2".to_string()),
                description: Some("Pub 2".to_string()),
                image: Some("URI 2".to_string()),
                ..Extension::default()
            }),
        });
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub2.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test not approved
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        // test owner is public for the contract
        let (init_result, mut deps) =
            init_helper_with_config(true, true, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub1.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub2.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            true,
        );
        assert!(check_perm.is_ok());

        // test owner makes their tokens private when the contract has public ownership
        let execute_msg = ExecuteMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            true,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        // test owner later makes ownership of a single token public
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        // test public approval when no address is given
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            None,
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test global approval for all tokens
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token2: Token = json_load(&info_store, &nft2_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token2: Token = json_load(&info_store, &nft2_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        // test public approval when no address is given
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            None,
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test those global permissions having expired
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(2000000),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(1),
            chain_id: "secret-2".to_string(),
            random: None,
        };

        // test whitelisted approval on a token
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT2".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(5)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token2: Token = json_load(&info_store, &nft2_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));

        // test approval expired
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(6),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("Access to token NFT2 has expired"));

        // test owner access
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token2,
            "NFT2",
            Some(&alice_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelisted approval on all tokens
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(7)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelisted ALL permission has expired
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(7),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("Access to all tokens of alice has expired"));

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub1.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub2.clone(),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test whitelist approval expired, but global is good on a token
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(100),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelist approval expired, but global is good on ALL tokens
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            transfer: None,
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(100),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelist approval is good, but global expired on a token
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(100),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // test whitelist approval is good, but global expired on ALL tokens
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            transfer: None,
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(100),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub1,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some("alice".to_string()),
            public_metadata: pub2,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test bob has view owner approval on NFT1 and view metadata approval on ALL
        // while there is global view owner approval on ALL tokens and global view metadata
        // approval on NFT1
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "bob".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::All),
            transfer: None,
            expires: Some(Expiration::AtTime(100)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(10)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(1),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        let error = extract_error_msg(check_perm);
        assert!(error.contains("not approved"));
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // now check where the global approvals expired
        let block = BlockInfo {
            height: 1,
            time: Timestamp::from_seconds(50),
            chain_id: "secret-2".to_string(),
            random: None,
        };
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewOwner,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&bob_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());

        // throw a charlie transfer approval and a view meta token approval in the mix
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(100)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: "charlie".to_string(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: Some(Expiration::AtTime(100)),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let info_store = ReadonlyPrefixedStorage::new(&deps.storage, PREFIX_INFOS);
        let token1: Token = json_load(&info_store, &nft1_key).unwrap();
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::Transfer,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
        let check_perm = check_permission(
            deps.as_ref(),
            &block,
            &token1,
            "NFT1",
            Some(&charlie_raw),
            PermissionType::ViewMetadata,
            &mut Vec::new(),
            "not approved",
            false,
        );
        assert!(check_perm.is_ok());
    }
}
