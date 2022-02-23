#[cfg(test)]
mod tests {
    use crate::contract::{handle, init, query};
    use crate::expiration::Expiration;
    use crate::mint_run::MintRunInfo;
    use crate::msg::{
        AccessLevel, BatchNftDossierElement, Cw721Approval, HandleMsg, InitConfig, InitMsg, Mint,
        QueryAnswer, QueryMsg, Snip721Approval, Tx, TxAction, ViewerInfo,
    };
    use crate::token::{Extension, Metadata};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, Binary, BlockInfo, Env, Extern, HumanAddr, InitResponse, MessageInfo,
        StdError, StdResult,
    };
    use std::any::Any;

    // Helper functions

    fn init_helper_default() -> (
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);
        let env = mock_env("instantiator", &[]);

        let init_msg = InitMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: None,
            post_init_callback: None,
        };

        (init(&mut deps, env, init_msg), deps)
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
        StdResult<InitResponse>,
        Extern<MockStorage, MockApi, MockQuerier>,
    ) {
        let mut deps = mock_dependencies(20, &[]);

        let env = mock_env("instantiator", &[]);
        let init_config: InitConfig = from_binary(&Binary::from(
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
        let init_msg = InitMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            entropy: "We're going to need a bigger boat".to_string(),
            royalty_info: None,
            config: Some(init_config),
            post_init_callback: None,
        };

        (init(&mut deps, env, init_msg), deps)
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

    // test ContractInfo query
    #[test]
    fn test_query_contract_info() {
        let (init_result, deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::ContractInfo {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ContractInfo { name, symbol } => {
                assert_eq!(name, "sec721".to_string());
                assert_eq!(symbol, "S721".to_string());
            }
            _ => panic!("unexpected"),
        }
    }

    // test ContractConfig query
    #[test]
    fn test_query_contract_config() {
        let (init_result, deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let query_msg = QueryMsg::ContractConfig {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ContractConfig {
                token_supply_is_public,
                owner_is_public,
                sealed_metadata_is_enabled,
                unwrapped_metadata_is_private,
                minter_may_update_metadata,
                owner_may_update_metadata,
                burn_is_enabled,
            } => {
                assert_eq!(token_supply_is_public, false);
                assert_eq!(owner_is_public, true);
                assert_eq!(sealed_metadata_is_enabled, true);
                assert_eq!(unwrapped_metadata_is_private, false);
                assert_eq!(minter_may_update_metadata, true);
                assert_eq!(owner_may_update_metadata, false);
                assert_eq!(burn_is_enabled, true);
            }
            _ => panic!("unexpected"),
        }
    }

    // test minters query
    #[test]
    fn test_query_minters() {
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let minters = vec![
            alice.clone(),
            bob.clone(),
            charlie.clone(),
            bob.clone(),
            alice.clone(),
        ];
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let query_msg = QueryMsg::Minters {};
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::Minters { minters } => {
                assert_eq!(minters.len(), 3);
                assert!(minters.contains(&alice));
                assert!(minters.contains(&bob));
                assert!(minters.contains(&charlie));
            }
            _ => panic!("unexpected"),
        }
    }

    // test NumTokens query
    #[test]
    fn test_query_num_tokens() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My1".to_string()),
                    description: Some("Public 1".to_string()),
                    image: Some("URI 1".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My2".to_string()),
                    description: Some("Public 2".to_string()),
                    image: Some("URI 2".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it

        // test non-minter attempt
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let minters = vec![
            alice.clone(),
            bob.clone(),
            charlie.clone(),
            bob.clone(),
            alice.clone(),
        ];
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let query_msg = QueryMsg::NumTokens { viewer: None };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("The token supply of this contract is private"));

        // test minter with bad viewing key
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "key".to_string(),
        };
        let query_msg = QueryMsg::NumTokens {
            viewer: Some(viewer.clone()),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key for this address or viewing key not set"));

        // test valid minter, valid key
        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::NumTokens {
            viewer: Some(viewer.clone()),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 2);
            }
            _ => panic!("unexpected"),
        }

        // test token supply public
        let (init_result, mut deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My1".to_string()),
                    description: Some("Public 1".to_string()),
                    image: Some("URI 1".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My2".to_string()),
                    description: Some("Public 2".to_string()),
                    image: Some("URI 2".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "key".to_string(),
        };
        let query_msg = QueryMsg::NumTokens {
            viewer: Some(viewer.clone()),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 2);
            }
            _ => panic!("unexpected"),
        }
    }

    // test AllTokens query
    #[test]
    fn test_query_all_tokens() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My1".to_string()),
                    description: Some("Public 1".to_string()),
                    image: Some("URI 1".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My2".to_string()),
                    description: Some("Public 2".to_string()),
                    image: Some("URI 2".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My3".to_string()),
                    description: Some("Public 3".to_string()),
                    image: Some("URI 3".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test non-minter attempt
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let minters = vec![
            alice.clone(),
            bob.clone(),
            charlie.clone(),
            bob.clone(),
            alice.clone(),
        ];
        let handle_msg = HandleMsg::SetMinters {
            minters: minters.clone(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let query_msg = QueryMsg::AllTokens {
            viewer: None,
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("The token supply of this contract is private"));

        // test minter with bad viewing key
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "key".to_string(),
        };
        let query_msg = QueryMsg::AllTokens {
            viewer: Some(viewer.clone()),
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key for this address or viewing key not set"));

        // test valid minter, valid key only return first two
        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::AllTokens {
            viewer: Some(viewer.clone()),
            start_after: None,
            limit: Some(2),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT2".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test token supply public, with pagination starting after NFT2
        let (init_result, mut deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My1".to_string()),
                    description: Some("Public 1".to_string()),
                    image: Some("URI 1".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My2".to_string()),
                    description: Some("Public 2".to_string()),
                    image: Some("URI 2".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My3".to_string()),
                    description: Some("Public 3".to_string()),
                    image: Some("URI 3".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My5".to_string()),
                    description: Some("Public 5".to_string()),
                    image: Some("URI 5".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                token_uri: None,
                extension: Some(Extension {
                    name: Some("My4".to_string()),
                    description: Some("Public 4".to_string()),
                    image: Some("URI 4".to_string()),
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
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "key".to_string(),
        };
        let query_msg = QueryMsg::AllTokens {
            viewer: Some(viewer.clone()),
            start_after: Some("NFT2".to_string()),
            limit: Some(10),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT3".to_string(), "NFT5".to_string(), "NFT4".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test start after token not found
        let query_msg = QueryMsg::AllTokens {
            viewer: Some(viewer.clone()),
            start_after: Some("NFT21".to_string()),
            limit: Some(10),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT21 not found"));

        // test burned token does not show
        let handle_msg = HandleMsg::BurnNft {
            token_id: "NFT3".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let query_msg = QueryMsg::AllTokens {
            viewer: Some(viewer.clone()),
            start_after: None,
            limit: Some(10),
        };
        let query_result = query(&deps, query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec![
                    "NFT1".to_string(),
                    "NFT2".to_string(),
                    "NFT5".to_string(),
                    "NFT4".to_string(),
                ];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
    }

    // test NftDossier query
    #[test]
    fn test_query_nft_dossier() {
        let (init_result, deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));

        let public_meta = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name1".to_string()),
                description: Some("PubDesc1".to_string()),
                image: Some("PubUri1".to_string()),
                ..Extension::default()
            }),
        };
        let private_meta = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("PrivName1".to_string()),
                description: Some("PrivDesc1".to_string()),
                image: Some("PrivUri1".to_string()),
                ..Extension::default()
            }),
        };
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // test viewer not given, contract has public ownership
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert!(private_metadata.is_none());
                assert_eq!(
                    display_private_metadata_error,
                    Some("You are not authorized to perform this action on token NFT1".to_string())
                );
                assert!(owner_is_public);
                assert!(transferable);
                assert!(!unwrapped);
                assert_eq!(public_ownership_expiration, Some(Expiration::Never));
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test viewer not given, contract has private ownership, but token ownership
        // and private metadata was made public
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(display_private_metadata_error.is_none());
                assert!(owner_is_public);
                assert!(transferable);
                assert!(unwrapped);
                assert_eq!(public_ownership_expiration, Some(Expiration::AtHeight(5)));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(5))
                );
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test no viewer given, ownership and private metadata made public at the
        // inventory level
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtTime(1000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 1,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(transferable);
                assert!(unwrapped);
                assert!(display_private_metadata_error.is_none());
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::AtHeight(5)));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtTime(1000))
                );
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test owner is the viewer including expired
        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "key".to_string(),
        };
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtHeight(10)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10000,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        let bob_tok_app = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: Some(Expiration::Never),
            transfer_expiration: None,
        };
        let char_tok_app = Snip721Approval {
            address: charlie.clone(),
            view_owner_expiration: Some(Expiration::AtHeight(5)),
            view_private_metadata_expiration: None,
            transfer_expiration: None,
        };
        let bob_all_app = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: Some(Expiration::Never),
            view_private_metadata_expiration: None,
            transfer_expiration: Some(Expiration::Never),
        };
        let char_all_app = Snip721Approval {
            address: charlie.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: None,
            transfer_expiration: Some(Expiration::AtHeight(5)),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(viewer.clone()),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(transferable);
                assert!(unwrapped);
                assert!(display_private_metadata_error.is_none());
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                let token_approvals = token_approvals.unwrap();
                assert_eq!(token_approvals.len(), 2);
                assert!(token_approvals.contains(&bob_tok_app));
                assert!(token_approvals.contains(&char_tok_app));
                let inventory_approvals = inventory_approvals.unwrap();
                assert_eq!(inventory_approvals.len(), 2);
                assert!(inventory_approvals.contains(&bob_all_app));
                assert!(inventory_approvals.contains(&char_all_app));
            }
            _ => panic!("unexpected"),
        }
        // test owner is the viewer, filtering expired
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(viewer.clone()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert_eq!(private_metadata, Some(private_meta.clone()));
                assert!(transferable);
                assert!(unwrapped);
                assert!(display_private_metadata_error.is_none());
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                let token_approvals = token_approvals.unwrap();
                assert_eq!(token_approvals.len(), 1);
                assert!(token_approvals.contains(&bob_tok_app));
                assert!(!token_approvals.contains(&char_tok_app));
                let inventory_approvals = inventory_approvals.unwrap();
                assert_eq!(inventory_approvals.len(), 1);
                assert!(inventory_approvals.contains(&bob_all_app));
                assert!(!inventory_approvals.contains(&char_all_app));
            }
            _ => panic!("unexpected"),
        }

        // test bad viewing key
        let viewer = ViewerInfo {
            address: alice.clone(),
            viewing_key: "ky".to_string(),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(viewer.clone()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key for this address or viewing key not set"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, true, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(5)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10,
                    time: 100,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // test owner is the viewer, but token is sealed
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "key".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert_eq!(owner, Some(alice.clone()));
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert!(private_metadata.is_none());
                assert!(transferable);
                assert!(!unwrapped);
                assert_eq!(display_private_metadata_error, Some("Sealed metadata of token NFT1 must be unwrapped by calling Reveal before it can be viewed".to_string()));
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                let token_approvals = token_approvals.unwrap();
                assert_eq!(token_approvals.len(), 1);
                assert!(token_approvals.contains(&bob_tok_app));
                assert!(!token_approvals.contains(&char_tok_app));
                let inventory_approvals = inventory_approvals.unwrap();
                assert_eq!(inventory_approvals.len(), 1);
                assert!(inventory_approvals.contains(&bob_all_app));
                assert!(!inventory_approvals.contains(&char_all_app));
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test expired view private meta approval
        let query_msg = QueryMsg::NftDossier {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier {
                owner,
                public_metadata,
                private_metadata,
                royalty_info: _,
                mint_run_info: _,
                transferable,
                unwrapped,
                display_private_metadata_error,
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
                inventory_approvals,
            } => {
                assert!(owner.is_none());
                assert_eq!(public_metadata, Some(public_meta.clone()));
                assert!(private_metadata.is_none());
                assert!(transferable);
                assert!(unwrapped);
                assert_eq!(
                    display_private_metadata_error,
                    Some("Access to token NFT1 has expired".to_string())
                );
                assert!(!owner_is_public);
                assert!(public_ownership_expiration.is_none());
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert!(token_approvals.is_none());
                assert!(inventory_approvals.is_none());
            }
            _ => panic!("unexpected"),
        }
    }

    // test Tokens query
    #[test]
    fn test_query_tokens() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT7".to_string()),
            owner: Some(HumanAddr("bob".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT8".to_string()),
            owner: Some(HumanAddr("charlie".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test contract has public ownership
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: None,
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec![
                    "NFT1".to_string(),
                    "NFT2".to_string(),
                    "NFT3".to_string(),
                    "NFT4".to_string(),
                    "NFT5".to_string(),
                    "NFT6".to_string(),
                ];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test a public inventory but not found
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: Some("NFT10".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT10 is not in the specified inventory"));

        // test not in a public inventory
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: Some("NFT7".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT7 is not in the specified inventory"));

        // test limit 0
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: None,
            limit: Some(0),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                assert!(tokens.is_empty());
            }
            _ => panic!("unexpected"),
        }

        // test limit 1, paginated
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: Some("NFT3".to_string()),
            limit: Some(1),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT4".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test no key provided should only see public tokens
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT3".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test viewer with a a token permission sees that one and the public ones
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some("bkey".to_string()),
            start_after: None,
            limit: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT3".to_string(), "NFT5".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test paginating with the owner querying
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: Some("akey".to_string()),
            start_after: None,
            limit: Some(3),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT1".to_string(), "NFT2".to_string(), "NFT3".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: Some("akey".to_string()),
            start_after: Some("NFT34".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT34 is not in the specified inventory"));

        // test setting all tokens public
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
            start_after: None,
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec![
                    "NFT1".to_string(),
                    "NFT2".to_string(),
                    "NFT3".to_string(),
                    "NFT4".to_string(),
                    "NFT5".to_string(),
                    "NFT6".to_string(),
                ];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // contract with private ownership
        let (init_result, mut deps) = init_helper_default();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let charlie = HumanAddr("charlie".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT4".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT5".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT6".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT7".to_string()),
            owner: Some(HumanAddr("bob".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT8".to_string()),
            owner: Some(HumanAddr("charlie".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT9".to_string()),
            owner: Some(HumanAddr("charlie".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT8".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: alice.clone(),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT5".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test a start after that is not in the inventory, but the viewer has permission on that token
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some("bkey".to_string()),
            start_after: Some("NFT8".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT8 is not in the specified inventory"));

        // test a start after that is not in the inventory, but viewer has token permission to view owner
        let query_msg = QueryMsg::Tokens {
            owner: charlie.clone(),
            viewer: Some(alice.clone()),
            viewing_key: Some("akey".to_string()),
            start_after: Some("NFT7".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT7"));

        // test viewer has permission on start after token (but no other) does not error
        let query_msg = QueryMsg::Tokens {
            owner: charlie.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some("bkey".to_string()),
            start_after: Some("NFT8".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                assert!(tokens.is_empty());
            }
            _ => panic!("unexpected"),
        }

        // test viewer has operator permission on start after token
        let query_msg = QueryMsg::Tokens {
            owner: charlie.clone(),
            viewer: Some(alice.clone()),
            viewing_key: Some("akey".to_string()),
            start_after: Some("NFT8".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenList { tokens } => {
                let expected = vec!["NFT9".to_string()];
                assert_eq!(tokens, expected);
            }
            _ => panic!("unexpected"),
        }

        // test a start after that viewer does not have permission on, although he does have permission
        // on other tokens in the inventory
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: Some(charlie.clone()),
            viewing_key: Some("ckey".to_string()),
            start_after: Some("NFT3".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT3"));

        // test a bad viewing key
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: None,
            viewing_key: Some("ckey".to_string()),
            start_after: Some("NFT3".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Wrong viewing key for this address or viewing key not set"));

        // test token not found with private supply and private ownership
        let query_msg = QueryMsg::Tokens {
            owner: alice.clone(),
            viewer: Some(charlie.clone()),
            viewing_key: Some("ckey".to_string()),
            start_after: Some("NFT34".to_string()),
            limit: Some(30),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT34"));
    }

    // test IsUnwrapped query
    #[test]
    fn test_is_unwrapped() {
        let (init_result, deps) =
            init_helper_with_config(true, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public and sealed meta is disabled
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private and sealed meta is disabled
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is private and sealed meta is enabled
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(!token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // sanity check, token sealed
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(!token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // sanity check, token unwrapped
        let query_msg = QueryMsg::IsUnwrapped {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::IsUnwrapped { token_is_unwrapped } => {
                assert!(token_is_unwrapped);
            }
            _ => panic!("unexpected"),
        }
    }

    // test OwnerOf query
    #[test]
    fn test_owner_of() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtTime(1000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test no viewer given, contract has public ownership
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert!(approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(100)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test viewer with no approvals, but token has public ownership
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert!(approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        // test viewer with no approval, but owner has made all his token ownership public
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert!(approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        // test not permitted to view owner
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::None),
            view_private_metadata: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: charlie.clone(),
                viewing_key: "ckey".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to view the owner of token NFT1"));

        // test owner can see approvals including expired
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        let bob_approv = Cw721Approval {
            spender: bob.clone(),
            expires: Expiration::AtHeight(100),
        };
        let char_approv = Cw721Approval {
            spender: charlie.clone(),
            expires: Expiration::AtHeight(1000),
        };

        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert_eq!(approvals.len(), 2);
                assert_eq!(approvals, vec![bob_approv.clone(), char_approv.clone()])
            }
            _ => panic!("unexpected"),
        }

        // test excluding expired
        let query_msg = QueryMsg::OwnerOf {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::OwnerOf { owner, approvals } => {
                assert_eq!(owner, alice.clone());
                assert_eq!(approvals, vec![char_approv.clone()])
            }
            _ => panic!("unexpected"),
        }
    }

    // test NftInfo query
    #[test]
    fn test_nft_info() {
        let (init_result, deps) =
            init_helper_with_config(true, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let query_msg = QueryMsg::NftInfo {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test token not found when supply is public
        let query_msg = QueryMsg::NftInfo {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftInfo {
                token_uri,
                extension,
            } => {
                assert!(token_uri.is_none());
                assert!(extension.is_none());
            }
            _ => panic!("unexpected"),
        }
        let alice = HumanAddr("alice".to_string());
        let public_meta = Metadata {
            token_uri: Some("uri".to_string()),
            extension: None,
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // sanity check
        let query_msg = QueryMsg::NftInfo {
            token_id: "NFT1".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftInfo {
                token_uri,
                extension,
            } => {
                assert_eq!(token_uri, public_meta.token_uri);
                assert_eq!(extension, public_meta.extension);
            }
            _ => panic!("unexpected"),
        }
    }

    // test AllNftInfo query
    #[test]
    fn test_all_nft_info() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let meta_for_fail = Metadata {
            token_uri: Some("uri".to_string()),
            extension: Some(Extension {
                name: Some("Name1".to_string()),
                description: Some("PubDesc1".to_string()),
                image: Some("PubUri1".to_string()),
                ..Extension::default()
            }),
        };

        let public_meta = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name1".to_string()),
                description: Some("PubDesc1".to_string()),
                image: Some("PubUri1".to_string()),
                ..Extension::default()
            }),
        };

        // test unable to have both token_uri and extension in the metadata
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFTfail".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(meta_for_fail.clone()),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Metadata can not have BOTH token_uri AND extension"));

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test don't have permission to view owner, but should still be able to see
        // public metadata
        let query_msg = QueryMsg::AllNftInfo {
            token_id: "NFT1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::AllNftInfo { access, info } => {
                assert!(access.owner.is_none());
                assert!(access.approvals.is_empty());
                assert_eq!(info, Some(public_meta.clone()));
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test owner viewing all nft info, the is no public metadata
        let query_msg = QueryMsg::AllNftInfo {
            token_id: "NFT2".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::AllNftInfo { access, info } => {
                assert_eq!(access.owner, Some(alice.clone()));
                assert_eq!(access.approvals.len(), 1);
                assert!(info.is_none());
            }
            _ => panic!("unexpected"),
        }
    }

    // test PrivateMetadata query
    #[test]
    fn test_private_metadata() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let private_meta = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name1".to_string()),
                description: Some("PrivDesc1".to_string()),
                image: Some("PrivUri1".to_string()),
                ..Extension::default()
            }),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: Some(private_meta.clone()),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test global approval on token
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                token_uri,
                extension,
            } => {
                assert_eq!(token_uri, private_meta.token_uri);
                assert_eq!(extension, private_meta.extension);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test global approval on all tokens
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                token_uri,
                extension,
            } => {
                assert_eq!(token_uri, private_meta.token_uri);
                assert_eq!(extension, private_meta.extension);
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, false, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetViewingKey {
            key: "bkey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        let private_meta = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name1".to_string()),
                description: Some("PrivDesc1".to_string()),
                image: Some("PrivUri1".to_string()),
                ..Extension::default()
            }),
        };
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: Some(private_meta.clone()),
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test trying to view sealed metadata
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains(
            "Sealed metadata must be unwrapped by calling Reveal before it can be viewed"
        ));
        let handle_msg = HandleMsg::Reveal {
            token_id: "NFT1".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test owner viewing empty metadata after the private got unwrapped to public
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: "akey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::PrivateMetadata {
                token_uri,
                extension,
            } => {
                assert!(token_uri.is_none());
                assert!(extension.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test viewer not permitted
        let query_msg = QueryMsg::PrivateMetadata {
            token_id: "NFT1".to_string(),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: "bkey".to_string(),
            }),
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to perform this action on token NFT1"));
    }

    // test ApprovedForAll query
    #[test]
    fn test_approved_for_all() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::ApproveAll {
            operator: bob.clone(),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::ApproveAll {
            operator: charlie.clone(),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test no viewing key supplied
        let query_msg = QueryMsg::ApprovedForAll {
            owner: alice.clone(),
            viewing_key: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ApprovedForAll { operators } => {
                assert!(operators.is_empty());
            }
            _ => panic!("unexpected"),
        }

        let bob_approv = Cw721Approval {
            spender: bob.clone(),
            expires: Expiration::Never,
        };
        let char_approv = Cw721Approval {
            spender: charlie.clone(),
            expires: Expiration::Never,
        };

        // sanity check
        let query_msg = QueryMsg::ApprovedForAll {
            owner: alice.clone(),
            viewing_key: Some("akey".to_string()),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::ApprovedForAll { operators } => {
                assert_eq!(operators, vec![bob_approv, char_approv]);
            }
            _ => panic!("unexpected"),
        }
    }

    // test TokenApprovals query
    #[test]
    fn test_token_approvals() {
        let (init_result, deps) =
            init_helper_with_config(true, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());

        // test token not found when supply is public
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT1 not found"));

        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // test token not found when supply is private
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("You are not authorized to view approvals for token NFT1"));

        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(2000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let bob_approv = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: Some(Expiration::Never),
            transfer_expiration: None,
        };

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // test public ownership when contract has public ownership
        // and private meta is public on the token
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::Never));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert_eq!(token_approvals, vec![bob_approv.clone()]);
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // test token has public ownership
        // and private meta is public for all of alice's tokens
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(
                    public_ownership_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert_eq!(token_approvals, vec![bob_approv.clone()]);
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::None),
            expires: Some(Expiration::AtHeight(2000000)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        // test all of alice's tokens have public ownership
        let query_msg = QueryMsg::TokenApprovals {
            token_id: "NFT1".to_string(),
            viewing_key: "akey".to_string(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TokenApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                token_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(
                    public_ownership_expiration,
                    Some(Expiration::AtHeight(2000000))
                );
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert_eq!(token_approvals, vec![bob_approv.clone()]);
            }
            _ => panic!("unexpected"),
        }
    }

    // test InventoryApprovals query
    #[test]
    fn test_inventory_approvals() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());

        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: None,
            view_private_metadata: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // test public ownership when contract has public ownership
        // and private metadata is public for all tokens
        let query_msg = QueryMsg::InventoryApprovals {
            address: alice.clone(),
            viewing_key: "akey".to_string(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::InventoryApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                inventory_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(public_ownership_expiration, Some(Expiration::Never));
                assert!(private_metadata_is_public);
                assert_eq!(
                    private_metadata_is_public_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert!(inventory_approvals.is_empty());
            }
            _ => panic!("unexpected"),
        }

        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("NFT1".to_string()),
            view_owner: None,
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: Some(Expiration::AtHeight(2000000)),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let bob_approv = Snip721Approval {
            address: bob.clone(),
            view_owner_expiration: None,
            view_private_metadata_expiration: None,
            transfer_expiration: Some(Expiration::AtHeight(2000000)),
        };

        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: Some(Expiration::AtHeight(1000000)),
            padding: None,
        };
        let _handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 500,
                    time: 1000000,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );

        // test owner makes ownership public for all tokens
        let query_msg = QueryMsg::InventoryApprovals {
            address: alice.clone(),
            viewing_key: "akey".to_string(),
            include_expired: Some(true),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::InventoryApprovals {
                owner_is_public,
                public_ownership_expiration,
                private_metadata_is_public,
                private_metadata_is_public_expiration,
                inventory_approvals,
            } => {
                assert!(owner_is_public);
                assert_eq!(
                    public_ownership_expiration,
                    Some(Expiration::AtHeight(1000000))
                );
                assert!(!private_metadata_is_public);
                assert!(private_metadata_is_public_expiration.is_none());
                assert_eq!(inventory_approvals, vec![bob_approv]);
            }
            _ => panic!("unexpected"),
        }
    }

    // test VerifyTransferApproval query
    #[test]
    fn test_verify_transfer_approval() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());
        let david = HumanAddr("david".to_string());

        let handle_msg = HandleMsg::SetViewingKey {
            key: "ckey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("charlie", &[]), handle_msg);

        let nft1 = "NFT1".to_string();
        let nft2 = "NFT2".to_string();
        let nft3 = "NFT3".to_string();
        let nft4 = "NFT4".to_string();
        let nft5 = "NFT5".to_string();

        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft1.clone()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft2.clone()),
            owner: Some(alice.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft3.clone()),
            owner: Some(bob.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft4.clone()),
            owner: Some(charlie.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some(nft5.clone()),
            owner: Some(david.clone()),
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: None,
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::All),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some(nft3.clone()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        // test that charlie can transfer nft1 and 2 with operator approval,
        // nft3 with token approval, and nft4 because he owns it
        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![nft1.clone(), nft2.clone(), nft3.clone(), nft4.clone()],
            address: charlie.clone(),
            viewing_key: "ckey".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(approved_for_all);
                assert!(first_unapproved_token.is_none());
            }
            _ => panic!("unexpected"),
        }

        // test an unknown token id
        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![
                nft1.clone(),
                nft2.clone(),
                "NFT10".to_string(),
                nft3.clone(),
                nft4.clone(),
            ],
            address: charlie.clone(),
            viewing_key: "ckey".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(!approved_for_all);
                assert_eq!(first_unapproved_token, Some("NFT10".to_string()));
            }
            _ => panic!("unexpected"),
        }

        // test not having approval on NFT5
        let query_msg = QueryMsg::VerifyTransferApproval {
            token_ids: vec![
                nft1.clone(),
                nft2.clone(),
                nft3.clone(),
                nft4.clone(),
                nft5.clone(),
            ],
            address: charlie.clone(),
            viewing_key: "ckey".to_string(),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::VerifyTransferApproval {
                approved_for_all,
                first_unapproved_token,
            } => {
                assert!(!approved_for_all);
                assert_eq!(first_unapproved_token, Some("NFT5".to_string()));
            }
            _ => panic!("unexpected"),
        }
    }

    // test TransactionHistory query
    #[test]
    fn test_transaction_history() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let admin = HumanAddr("admin".to_string());
        let alice = HumanAddr("alice".to_string());
        let handle_msg = HandleMsg::SetViewingKey {
            key: "akey".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        let handle_msg = HandleMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        // test no txs yet
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert!(txs.is_empty());
                assert_eq!(total, 0);
            }
            _ => panic!("unexpected"),
        }
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT1".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::MintNft {
            token_id: Some("NFT2".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            serial_number: None,
            transferable: None,
            memo: Some("Mint 2".to_string()),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::TransferNft {
            token_id: "NFT1".to_string(),
            recipient: alice.clone(),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::BurnNft {
            token_id: "NFT2".to_string(),
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);

        let mint1 = Tx {
            tx_id: 0,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT1".to_string(),
            memo: None,
            action: TxAction::Mint {
                minter: admin.clone(),
                recipient: admin.clone(),
            },
        };
        let mint2 = Tx {
            tx_id: 1,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT2".to_string(),
            memo: Some("Mint 2".to_string()),
            action: TxAction::Mint {
                minter: admin.clone(),
                recipient: admin.clone(),
            },
        };
        let xfer1 = Tx {
            tx_id: 2,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT1".to_string(),
            memo: None,
            action: TxAction::Transfer {
                from: admin.clone(),
                sender: None,
                recipient: alice.clone(),
            },
        };
        let burn2 = Tx {
            tx_id: 3,
            block_height: 12345,
            block_time: 1571797419,
            token_id: "NFT2".to_string(),
            memo: None,
            action: TxAction::Burn {
                owner: admin.clone(),
                burner: None,
            },
        };

        // sanity check for all txs
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert_eq!(
                    txs,
                    vec![burn2.clone(), xfer1.clone(), mint2.clone(), mint1.clone()]
                );
                assert_eq!(total, 4);
            }
            _ => panic!("unexpected"),
        }

        // test paginating so only see last 2
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: None,
            page_size: Some(2),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert_eq!(txs, vec![burn2.clone(), xfer1.clone()]);
                assert_eq!(total, 4);
            }
            _ => panic!("unexpected"),
        }

        // test paginating so only see 3rd one
        let query_msg = QueryMsg::TransactionHistory {
            address: admin.clone(),
            viewing_key: "key".to_string(),
            page: Some(2),
            page_size: Some(1),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert_eq!(txs, vec![mint2.clone()]);
                assert_eq!(total, 4);
            }
            _ => panic!("unexpected"),
        }

        // test tx was logged to all participants
        let query_msg = QueryMsg::TransactionHistory {
            address: alice.clone(),
            viewing_key: "akey".to_string(),
            page: None,
            page_size: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::TransactionHistory { total, txs } => {
                assert_eq!(txs, vec![xfer1.clone()]);
                assert_eq!(total, 1);
            }
            _ => panic!("unexpected"),
        }
    }

    // test RegisteredCodeHash query
    #[test]
    fn test_query_registered_code_hash() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, true, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test not registered
        let query_msg = QueryMsg::RegisteredCodeHash {
            contract: HumanAddr("alice".to_string()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RegisteredCodeHash {
                code_hash,
                also_implements_batch_receive_nft,
            } => {
                assert!(code_hash.is_none());
                assert!(!also_implements_batch_receive_nft)
            }
            _ => panic!("unexpected"),
        }

        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "Code Hash".to_string(),
            also_implements_batch_receive_nft: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);

        // sanity check with default for implements BatchReceiveNft
        let query_msg = QueryMsg::RegisteredCodeHash {
            contract: HumanAddr("alice".to_string()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RegisteredCodeHash {
                code_hash,
                also_implements_batch_receive_nft,
            } => {
                assert_eq!(code_hash, Some("Code Hash".to_string()));
                assert!(!also_implements_batch_receive_nft)
            }
            _ => panic!("unexpected"),
        }

        // sanity check with implementing BatchRegisterReceive
        let handle_msg = HandleMsg::RegisterReceiveNft {
            code_hash: "Code Hash".to_string(),
            also_implements_batch_receive_nft: Some(true),
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("bob", &[]), handle_msg);

        let query_msg = QueryMsg::RegisteredCodeHash {
            contract: HumanAddr("bob".to_string()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RegisteredCodeHash {
                code_hash,
                also_implements_batch_receive_nft,
            } => {
                assert_eq!(code_hash, Some("Code Hash".to_string()));
                assert!(also_implements_batch_receive_nft)
            }
            _ => panic!("unexpected"),
        }
    }

    // test NumTokensOfOwner query
    #[test]
    fn test_num_tokens_of_owner() {
        let (init_result, mut deps) =
            init_helper_with_config(false, true, false, false, false, false, false);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let alice = HumanAddr("alice".to_string());
        let alice_key = "akey".to_string();
        let bob = HumanAddr("bob".to_string());
        let bob_key = "bkey".to_string();
        let charlie = HumanAddr("charlie".to_string());
        let charlie_key = "ckey".to_string();

        let mints = vec![
            Mint {
                token_id: Some("NFT1".to_string()),
                owner: Some(alice.clone()),
                public_metadata: None,
                private_metadata: None,
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT2".to_string()),
                owner: Some(alice.clone()),
                public_metadata: None,
                private_metadata: None,
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT3".to_string()),
                owner: Some(alice.clone()),
                public_metadata: None,
                private_metadata: None,
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
        ];

        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // let charlie see the owner of NFT2 until time 55
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: charlie.clone(),
            token_id: Some("NFT2".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtTime(55)),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 2,
                    time: 2,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test all 3 are public from the config
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 3);
            }
            _ => panic!("unexpected"),
        }

        // set ownership to private for alice
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 3,
                    time: 3,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // set charlie's viewing key
        let handle_msg = HandleMsg::SetViewingKey {
            key: charlie_key.clone(),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 3,
                    time: 3,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("charlie".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test that charlie can only know of NFT2
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: Some(charlie.clone()),
            viewing_key: Some(charlie_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 1);
            }
            _ => panic!("unexpected"),
        }

        // set alice's viewing key
        let handle_msg = HandleMsg::SetViewingKey {
            key: alice_key.clone(),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 4,
                    time: 4,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test that alice knows of all her tokens
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: None,
            viewing_key: Some(alice_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 3);
            }
            _ => panic!("unexpected"),
        }

        // make ownership public until time 15
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            expires: Some(Expiration::AtTime(15)),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10,
                    time: 10,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // set bob's viewing key
        let handle_msg = HandleMsg::SetViewingKey {
            key: bob_key.clone(),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 10,
                    time: 10,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("bob".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test that bob can use the global approval to know of all 3
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some(bob_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 3);
            }
            _ => panic!("unexpected"),
        }

        // let bob see all alice ownership until time 25
        let handle_msg = HandleMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: None,
            view_owner: Some(AccessLevel::All),
            view_private_metadata: None,
            transfer: None,
            expires: Some(Expiration::AtTime(25)),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 20,
                    time: 20,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test that the global approval has expired
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: None,
            viewing_key: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 0);
            }
            _ => panic!("unexpected"),
        }

        // test that bob can use his approval to know of all 3 now that global has expired
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some(bob_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 3);
            }
            _ => panic!("unexpected"),
        }

        // make ownership public for NFT2 until time 25
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT2".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtTime(25)),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 22,
                    time: 22,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // make ownership public for NFT1 until time 50
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT1".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtTime(50)),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 25,
                    time: 25,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // make ownership public for NFT3 until time 60
        let handle_msg = HandleMsg::SetGlobalApproval {
            token_id: Some("NFT3".to_string()),
            view_owner: Some(AccessLevel::ApproveToken),
            view_private_metadata: None,
            expires: Some(Expiration::AtTime(60)),
            padding: None,
        };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 30,
                    time: 30,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test that charlie knows of all of them by using the two global approvals and his own
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: Some(charlie.clone()),
            viewing_key: Some(charlie_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 3);
            }
            _ => panic!("unexpected"),
        }

        // test that bob knows of NFT1 and NFT3 by using the two global approvals
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: Some(bob.clone()),
            viewing_key: Some(bob_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 2);
            }
            _ => panic!("unexpected"),
        }

        // set ownership to private for alice again just to change the saved blockinfo
        let handle_msg = HandleMsg::MakeOwnershipPrivate { padding: None };
        let handle_result = handle(
            &mut deps,
            Env {
                block: BlockInfo {
                    height: 57,
                    time: 57,
                    chain_id: "cosmos-testnet-14002".to_string(),
                },
                message: MessageInfo {
                    sender: HumanAddr("alice".to_string()),
                    sent_funds: vec![],
                },
                contract: cosmwasm_std::ContractInfo {
                    address: HumanAddr::from(MOCK_CONTRACT_ADDR),
                },
                contract_key: Some("".to_string()),
                contract_code_hash: "".to_string(),
            },
            handle_msg,
        );
        assert!(handle_result.is_ok());

        // test that charlie only knows of NFT3 now that the other two approvals expired
        let query_msg = QueryMsg::NumTokensOfOwner {
            owner: alice.clone(),
            viewer: Some(charlie.clone()),
            viewing_key: Some(charlie_key.clone()),
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NumTokens { count } => {
                assert_eq!(count, 1);
            }
            _ => panic!("unexpected"),
        }
    }

    // test BatchNftDossier query
    #[test]
    fn test_query_batch_nft_dossier() {
        let (init_result, mut deps) =
            init_helper_with_config(false, false, false, false, true, false, true);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let alice = HumanAddr("alice".to_string());

        let public_meta1 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name1".to_string()),
                description: Some("PubDesc1".to_string()),
                image: Some("PubUri1".to_string()),
                ..Extension::default()
            }),
        };
        let private_meta1 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("PrivName1".to_string()),
                description: Some("PrivDesc1".to_string()),
                image: Some("PrivUri1".to_string()),
                ..Extension::default()
            }),
        };
        let public_meta2 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name2".to_string()),
                description: Some("PubDesc2".to_string()),
                image: Some("PubUri2".to_string()),
                ..Extension::default()
            }),
        };
        let private_meta2 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("PrivName2".to_string()),
                description: Some("PrivDesc2".to_string()),
                image: Some("PrivUri2".to_string()),
                ..Extension::default()
            }),
        };

        let public_meta3 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("Name3".to_string()),
                description: Some("PubDesc3".to_string()),
                image: Some("PubUri3".to_string()),
                ..Extension::default()
            }),
        };
        let private_meta3 = Metadata {
            token_uri: None,
            extension: Some(Extension {
                name: Some("PrivName3".to_string()),
                description: Some("PrivDesc3".to_string()),
                image: Some("PrivUri3".to_string()),
                ..Extension::default()
            }),
        };

        let mints = vec![
            Mint {
                token_id: Some("NFT1".to_string()),
                owner: Some(alice.clone()),
                public_metadata: Some(public_meta1.clone()),
                private_metadata: Some(private_meta1.clone()),
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT2".to_string()),
                owner: Some(alice.clone()),
                public_metadata: Some(public_meta2.clone()),
                private_metadata: Some(private_meta2.clone()),
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
            Mint {
                token_id: Some("NFT3".to_string()),
                owner: Some(HumanAddr("bob".to_string())),
                public_metadata: Some(public_meta3.clone()),
                private_metadata: Some(private_meta3.clone()),
                royalty_info: None,
                serial_number: None,
                transferable: None,
                memo: None,
            },
        ];

        let handle_msg = HandleMsg::BatchMintNft {
            mints: mints.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());

        // test querying all 3
        let alice_key = "akey".to_string();
        let handle_msg = HandleMsg::SetViewingKey {
            key: alice_key.clone(),
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let query_msg = QueryMsg::BatchNftDossier {
            token_ids: vec!["NFT1".to_string(), "NFT2".to_string(), "NFT3".to_string()],
            viewer: Some(ViewerInfo {
                address: alice.clone(),
                viewing_key: alice_key.clone(),
            }),
            include_expired: None,
        };
        let mint_run_info = MintRunInfo {
            collection_creator: Some(HumanAddr("instantiator".to_string())),
            token_creator: Some(HumanAddr("admin".to_string())),
            time_of_minting: Some(1571797419),
            mint_run: None,
            serial_number: None,
            quantity_minted_this_run: None,
        };
        let expected = vec![
            BatchNftDossierElement {
                token_id: "NFT1".to_string(),
                owner: Some(alice.clone()),
                public_metadata: Some(public_meta1),
                private_metadata: Some(private_meta1),
                display_private_metadata_error: None,
                royalty_info: None,
                mint_run_info: Some(mint_run_info.clone()),
                transferable: true,
                unwrapped: true,
                owner_is_public: false,
                public_ownership_expiration: None,
                private_metadata_is_public: false,
                private_metadata_is_public_expiration: None,
                token_approvals: Some(Vec::new()),
                inventory_approvals: Some(Vec::new()),
            },
            BatchNftDossierElement {
                token_id: "NFT2".to_string(),
                owner: Some(alice.clone()),
                public_metadata: Some(public_meta2),
                private_metadata: Some(private_meta2),
                display_private_metadata_error: None,
                royalty_info: None,
                mint_run_info: Some(mint_run_info.clone()),
                transferable: true,
                unwrapped: true,
                owner_is_public: false,
                public_ownership_expiration: None,
                private_metadata_is_public: false,
                private_metadata_is_public_expiration: None,
                token_approvals: Some(Vec::new()),
                inventory_approvals: Some(Vec::new()),
            },
            // last one belongs to bob, so you can only see public info
            BatchNftDossierElement {
                token_id: "NFT3".to_string(),
                owner: None,
                public_metadata: Some(public_meta3),
                private_metadata: None,
                display_private_metadata_error: Some(
                    "You are not authorized to perform this action on token NFT3".to_string(),
                ),
                royalty_info: None,
                mint_run_info: Some(mint_run_info.clone()),
                transferable: true,
                unwrapped: true,
                owner_is_public: false,
                public_ownership_expiration: None,
                private_metadata_is_public: false,
                private_metadata_is_public_expiration: None,
                token_approvals: None,
                inventory_approvals: None,
            },
        ];
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::BatchNftDossier { nft_dossiers } => {
                assert_eq!(nft_dossiers, expected);
            }
            _ => panic!("unexpected"),
        }
    }
}
