#[cfg(test)]
mod tests {
    use std::any::Any;

    use cosmwasm_std::testing::*;
    use cosmwasm_std::{
        from_binary, to_binary, Addr, Api, Binary, Coin, OwnedDeps, Response, StdError, StdResult,
        SubMsg, Uint128, WasmMsg,
    };

    use crate::contract::{execute, instantiate, query};
    use crate::msg::{
        AccessLevel, ContractStatus, ExecuteMsg, InstantiateConfig, InstantiateMsg,
        PostInstantiateCallback, QueryAnswer, QueryMsg, ViewerInfo,
    };
    use crate::royalties::{DisplayRoyalty, DisplayRoyaltyInfo, Royalty, RoyaltyInfo};
    use crate::state::{load, Config, CONFIG_KEY};

    // Helper functions

    fn init_helper_royalties(
        royalty_info: Option<RoyaltyInfo>,
    ) -> (
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
            royalty_info,
            config: None,
            post_init_callback: None,
        };

        (instantiate(deps.as_mut(), env, info, init_msg), deps)
    }

    #[allow(clippy::too_many_arguments)]
    fn init_helper_royalties_with_config(
        royalty_info: Option<RoyaltyInfo>,
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
            royalty_info,
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

    // Init tests

    #[test]
    fn test_init_sanity() {
        let royalties = RoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                Royalty {
                    recipient: "alice".to_string(),
                    rate: 10,
                },
                Royalty {
                    recipient: "bob".to_string(),
                    rate: 5,
                },
            ],
        };

        // test default config
        let (init_result, mut deps) = init_helper_royalties(Some(royalties.clone()));
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

        let expected_see = DisplayRoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                DisplayRoyalty {
                    recipient: Some(Addr::unchecked("alice".to_string())),
                    rate: 10,
                },
                DisplayRoyalty {
                    recipient: Some(Addr::unchecked("bob".to_string())),
                    rate: 5,
                },
            ],
        };

        let expected_hidden = DisplayRoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                DisplayRoyalty {
                    recipient: None,
                    rate: 10,
                },
                DisplayRoyalty {
                    recipient: None,
                    rate: 5,
                },
            ],
        };

        // test viewer not permitted to see default royalty addresses
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(expected_hidden.clone()));
            }
            _ => panic!("unexpected"),
        }

        let execute_msg = ExecuteMsg::SetViewingKey {
            key: "key".to_string(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        // test viewer is permitted to see default royatly addresses
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: Some(ViewerInfo {
                address: "admin".to_string(),
                viewing_key: "key".to_string(),
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(expected_see));
            }
            _ => panic!("unexpected"),
        }

        // test config specification
        let (init_result, deps) = init_helper_royalties_with_config(
            Some(royalties),
            true,
            true,
            true,
            true,
            false,
            true,
            false,
        );
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

        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(expected_hidden));
            }
            _ => panic!("unexpected"),
        }

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

    // test setting royalty info
    #[test]
    fn test_set_royalty_info() {
        let (init_result, mut deps) = init_helper_royalties(None);
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        let royalties = RoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                Royalty {
                    recipient: "steven".to_string(),
                    rate: 10,
                },
                Royalty {
                    recipient: "thomas".to_string(),
                    rate: 5,
                },
            ],
        };

        // test non-minter attempting to set default royalties
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: None,
            royalty_info: Some(royalties.clone()),
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
            error.contains("Only designated minters can set default royalties for the contract")
        );

        // test royalties more than 100%
        let royalty_info_for_failure = RoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                Royalty {
                    recipient: "steven".to_string(),
                    rate: 80,
                },
                Royalty {
                    recipient: "thomas".to_string(),
                    rate: 20,
                },
                Royalty {
                    recipient: "uriel".to_string(),
                    rate: 1,
                },
            ],
        };
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: None,
            royalty_info: Some(royalty_info_for_failure),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("The sum of royalty rates must not exceed 100%"));

        // verify no default royalties are set
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, None);
            }
            _ => panic!("unexpected"),
        }

        let expected_hidden = DisplayRoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                DisplayRoyalty {
                    recipient: None,
                    rate: 10,
                },
                DisplayRoyalty {
                    recipient: None,
                    rate: 5,
                },
            ],
        };

        let expected_see = DisplayRoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![
                DisplayRoyalty {
                    recipient: Some(Addr::unchecked("steven".to_string())),
                    rate: 10,
                },
                DisplayRoyalty {
                    recipient: Some(Addr::unchecked("thomas".to_string())),
                    rate: 5,
                },
            ],
        };
        let admin = "admin".to_string();
        let admin_key = "key".to_string();
        let alice = "alice".to_string();
        let alice_key = "akey".to_string();
        let bob = "bob".to_string();
        let bob_key = "bkey".to_string();

        // test unknown token error when supply is private but a minter is querying
        let execute_msg = ExecuteMsg::SetViewingKey {
            key: admin_key.clone(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetViewingKey {
            key: alice_key.clone(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );

        let execute_msg = ExecuteMsg::SetViewingKey {
            key: bob_key.clone(),
            padding: None,
        };
        let _handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("bob", &[]),
            execute_msg,
        );

        // set default royalties sanity check
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: None,
            royalty_info: Some(royalties.clone()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(expected_hidden.clone()));
            }
            _ => panic!("unexpected"),
        }

        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: Some(ViewerInfo {
                address: admin.clone(),
                viewing_key: admin_key.clone(),
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(expected_see));
            }
            _ => panic!("unexpected"),
        }

        // test unknown token error during query when supply is private
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("NFT".to_string()),
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(expected_hidden));
            }
            _ => panic!("unexpected"),
        }

        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("NFT".to_string()),
            viewer: Some(ViewerInfo {
                address: admin.clone(),
                viewing_key: admin_key.clone(),
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT not found"));

        // verify default gets deleted
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: None,
            royalty_info: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        assert!(
            query_result.is_ok(),
            "query failed: {}",
            query_result.err().unwrap()
        );
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, None);
            }
            _ => panic!("unexpected"),
        }

        // test unknown token id error when supply is private
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: Some("NFT".to_string()),
            royalty_info: Some(royalties.clone()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("A token's RoyaltyInfo may only be set by the token creator when they are also the token owner"));

        let default = RoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![Royalty {
                recipient: "default".to_string(),
                rate: 10,
            }],
        };
        let individual = RoyaltyInfo {
            decimal_places_in_rates: 3,
            royalties: vec![Royalty {
                recipient: "individual".to_string(),
                rate: 10,
            }],
        };
        let default_hide = DisplayRoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![DisplayRoyalty {
                recipient: None,
                rate: 10,
            }],
        };
        let default_see = DisplayRoyaltyInfo {
            decimal_places_in_rates: 2,
            royalties: vec![DisplayRoyalty {
                recipient: Some(Addr::unchecked("default".to_string())),
                rate: 10,
            }],
        };
        let individual_hide = DisplayRoyaltyInfo {
            decimal_places_in_rates: 3,
            royalties: vec![DisplayRoyalty {
                recipient: None,
                rate: 10,
            }],
        };
        let individual_see = DisplayRoyaltyInfo {
            decimal_places_in_rates: 3,
            royalties: vec![DisplayRoyalty {
                recipient: Some(Addr::unchecked("individual".to_string())),
                rate: 10,
            }],
        };
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: None,
            royalty_info: Some(default),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("default".to_string()),
            owner: Some(alice.clone()),
            public_metadata: None,
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
        assert!(handle_result.is_ok());

        // verify it has the default royalties with hidden addresses for bob
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("default".to_string()),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: bob_key.clone(),
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(default_hide));
            }
            _ => panic!("unexpected"),
        }

        // verify it has the default royalties with viewable addresses for alice
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("default".to_string()),
            viewer: Some(ViewerInfo {
                address: alice,
                viewing_key: alice_key,
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(default_see.clone()));
            }
            _ => panic!("unexpected"),
        }

        let execute_msg = ExecuteMsg::MintNft {
            token_id: Some("specified".to_string()),
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: Some(individual.clone()),
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
        assert!(handle_result.is_ok());

        // verify whitelisting bob for anything but transfer does not reveal addresses
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("specified".to_string()),
            view_owner: Some(AccessLevel::All),
            view_private_metadata: Some(AccessLevel::ApproveToken),
            transfer: None,
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());

        // verify it has the individual royalties with hidden addresses
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("specified".to_string()),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: bob_key.clone(),
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(individual_hide.clone()));
            }
            _ => panic!("unexpected"),
        }

        // verify nft_dossier also hides addresses
        let query_msg = QueryMsg::NftDossier {
            token_id: "specified".to_string(),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: bob_key.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { royalty_info, .. } => {
                assert_eq!(royalty_info, Some(individual_hide));
            }
            _ => panic!("unexpected"),
        }

        // verify that whitelisting bob for transfers reveals the royalty addresses
        let execute_msg = ExecuteMsg::SetWhitelistedApproval {
            address: bob.clone(),
            token_id: Some("specified".to_string()),
            view_owner: None,
            view_private_metadata: None,
            transfer: Some(AccessLevel::ApproveToken),
            expires: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());

        let query_msg = QueryMsg::NftDossier {
            token_id: "specified".to_string(),
            viewer: Some(ViewerInfo {
                address: bob.clone(),
                viewing_key: bob_key.clone(),
            }),
            include_expired: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { royalty_info, .. } => {
                assert_eq!(royalty_info, Some(individual_see));
            }
            _ => panic!("unexpected"),
        }

        // verify contract default
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: None,
            viewer: Some(ViewerInfo {
                address: admin,
                viewing_key: admin_key,
            }),
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info } => {
                assert_eq!(royalty_info, Some(default_see.clone()));
            }
            _ => panic!("unexpected"),
        }

        // test setting royalties for a token if not owner
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: Some("default".to_string()),
            royalty_info: Some(individual.clone()),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("A token's RoyaltyInfo may only be set by the token creator when they are also the token owner"));

        // test trying to set royalties for a token if not the creator
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: Some("default".to_string()),
            royalty_info: Some(individual),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("alice", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("A token's RoyaltyInfo may only be set by the token creator when they are also the token owner"));

        // test that deleting individual royalties updates the token to use the default
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: Some("specified".to_string()),
            royalty_info: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());
        let query_msg = QueryMsg::NftDossier {
            token_id: "specified".to_string(),
            viewer: Some(ViewerInfo {
                address: bob,
                viewing_key: bob_key,
            }),
            include_expired: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { royalty_info, .. } => {
                assert_eq!(royalty_info, Some(default_see));
            }
            _ => panic!("unexpected"),
        }

        // delete the default royalties
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: None,
            royalty_info: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());

        // test that deleting a token's royalties when there is no default, results in no royalties
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: Some("specified".to_string()),
            royalty_info: None,
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        assert!(handle_result.is_ok());
        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("specified".to_string()),
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::RoyaltyInfo { royalty_info, .. } => {
                assert_eq!(royalty_info, None);
            }
            _ => panic!("unexpected"),
        }

        // test unknown token id when supply is public
        let (init_result, mut deps) = init_helper_royalties_with_config(
            Some(royalties.clone()),
            true,
            true,
            true,
            true,
            false,
            true,
            false,
        );
        assert_eq!(init_result.unwrap(), Response::default());
        // test unknown token id error when supply is private
        let execute_msg = ExecuteMsg::SetRoyaltyInfo {
            token_id: Some("NFT".to_string()),
            royalty_info: Some(royalties),
            padding: None,
        };
        let handle_result = execute(
            deps.as_mut(),
            mock_env(),
            mock_info("admin", &[]),
            execute_msg,
        );
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Token ID: NFT not found"));

        let query_msg = QueryMsg::RoyaltyInfo {
            token_id: Some("NFT".to_string()),
            viewer: None,
        };
        let query_result = query(deps.as_ref(), mock_env(), query_msg);
        let error = extract_error_msg(query_result);
        assert!(error.contains("Token ID: NFT not found"));
    }
}
