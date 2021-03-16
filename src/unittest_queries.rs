#[cfg(test)]
mod tests {
    use crate::contract::{check_permission, handle, init, query};
    use crate::expiration::Expiration;
    use crate::msg::{
        AccessLevel, Burn, ContractStatus, HandleAnswer, HandleMsg, InitConfig, InitMsg,
        QueryAnswer, QueryMsg, Send, Snip721Approval, Transfer, ViewerInfo,
    };
    use crate::receiver::receive_nft_msg;
    use crate::state::{
        get_txs, json_load, json_may_load, load, may_load, AuthList, Config, Permission,
        PermissionType, TxAction, CONFIG_KEY, IDS_KEY, INDEX_KEY, MINTERS_KEY,
        PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST, PREFIX_INFOS, PREFIX_OWNED, PREFIX_OWNER_PRIV,
        PREFIX_PRIV_META, PREFIX_PUB_META, PREFIX_RECEIVERS, PREFIX_VIEW_KEY,
    };
    use crate::token::{Metadata, Token};
    use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, to_binary, Api, Binary, BlockInfo, CanonicalAddr, Env, Extern, HandleResponse,
        HumanAddr, InitResponse, MessageInfo, QueryResponse, StdError, StdResult, WasmMsg,
    };
    use cosmwasm_storage::ReadonlyPrefixedStorage;

    use std::any::Any;
    use std::collections::{HashMap, HashSet};

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
            config: None,
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
                enable_burn
            )
            .as_bytes(),
        ))
        .unwrap();
        let init_msg = InitMsg {
            name: "sec721".to_string(),
            symbol: "S721".to_string(),
            admin: Some(HumanAddr("admin".to_string())),
            entropy: "We're going to need a bigger boat".to_string(),
            config: Some(init_config),
        };

        (init(&mut deps, env, init_msg), deps)
    }

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(_response) => panic!("Expected error, but had Ok response"),
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!(format!("Unexpected error result {:?}", err)),
            },
        }
    }
    /*
        fn extract_log(resp: StdResult<HandleResponse>) -> String {
            match resp {
                Ok(response) => response.log[0].value.clone(),
                Err(_err) => "These are not the logs you are looking for".to_string(),
            }
        }
    */

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

        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Public 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Public 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
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

        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Public 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Public 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
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

        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Public 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Public 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My3".to_string()),
                description: Some("Public 3".to_string()),
                image: Some("URI 3".to_string()),
            }),
            private_metadata: None,
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

        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT1".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My1".to_string()),
                description: Some("Public 1".to_string()),
                image: Some("URI 1".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT2".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My2".to_string()),
                description: Some("Public 2".to_string()),
                image: Some("URI 2".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT3".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My3".to_string()),
                description: Some("Public 3".to_string()),
                image: Some("URI 3".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT5".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My5".to_string()),
                description: Some("Public 5".to_string()),
                image: Some("URI 5".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT4".to_string()),
            owner: Some(HumanAddr("alice".to_string())),
            public_metadata: Some(Metadata {
                name: Some("My4".to_string()),
                description: Some("Public 4".to_string()),
                image: Some("URI 4".to_string()),
            }),
            private_metadata: None,
            memo: None,
            padding: None,
        };
        let _handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg); // test burn when status prevents it
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
                let expected = vec!["NFT3".to_string(), "NFT4".to_string(), "NFT5".to_string()];
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
            name: Some("Name1".to_string()),
            description: Some("PubDesc1".to_string()),
            image: Some("PubUri1".to_string()),
        };
        let private_meta = Metadata {
            name: Some("PrivName1".to_string()),
            description: Some("PrivDesc1".to_string()),
            image: Some("PrivUri1".to_string()),
        };
        let alice = HumanAddr("alice".to_string());
        let bob = HumanAddr("bob".to_string());
        let charlie = HumanAddr("charlie".to_string());

        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
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
                assert!(owner_is_public);
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

        let handle_msg = HandleMsg::Mint {
            token_id: Some("NFT1".to_string()),
            owner: Some(alice.clone()),
            public_metadata: Some(public_meta.clone()),
            private_metadata: Some(private_meta.clone()),
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
                assert!(owner_is_public);
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
    }
}
