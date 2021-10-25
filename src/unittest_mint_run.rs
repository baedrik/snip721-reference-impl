#[cfg(test)]
mod tests {
    use crate::contract::{handle, init, query};
    use crate::mint_run::MintRunInfo;
    use crate::msg::{HandleMsg, InitMsg, QueryAnswer, QueryMsg};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{from_binary, Extern, HumanAddr, InitResponse, StdError, StdResult};
    use std::any::Any;

    // Helper functions

    fn init_helper() -> (
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

    fn extract_error_msg<T: Any>(error: StdResult<T>) -> String {
        match error {
            Ok(_response) => panic!("Expected error, but had Ok response"),
            Err(err) => match err {
                StdError::GenericErr { msg, .. } => msg,
                _ => panic!("Unexpected error result {:?}", err),
            },
        }
    }

    // test mint run info
    #[test]
    fn test_mint_run_info() {
        let (init_result, mut deps) = init_helper();
        assert!(
            init_result.is_ok(),
            "Init failed: {}",
            init_result.err().unwrap()
        );

        // test non-minter attempt
        let handle_msg = HandleMsg::MintNftClones {
            mint_run_id: None,
            quantity: 1,
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("alice", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Only designated minters are allowed to mint"));

        // test 0 quantity
        let handle_msg = HandleMsg::MintNftClones {
            mint_run_id: None,
            quantity: 0,
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        let error = extract_error_msg(handle_result);
        assert!(error.contains("Quantity can not be zero"));

        // test no mint_run_id
        let handle_msg = HandleMsg::MintNftClones {
            mint_run_id: None,
            quantity: 3,
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());
        let instantiator = HumanAddr("instantiator".to_string());
        let admin = HumanAddr("admin".to_string());
        let run_info_0 = MintRunInfo {
            collection_creator: Some(instantiator.clone()),
            token_creator: Some(admin.clone()),
            time_of_minting: Some(1571797419),
            mint_run: None,
            serial_number: Some(1),
            quantity_minted_this_run: Some(3),
        };
        let run_info_1 = MintRunInfo {
            collection_creator: Some(instantiator.clone()),
            token_creator: Some(admin.clone()),
            time_of_minting: Some(1571797419),
            mint_run: None,
            serial_number: Some(2),
            quantity_minted_this_run: Some(3),
        };
        let run_info_2 = MintRunInfo {
            collection_creator: Some(instantiator.clone()),
            token_creator: Some(admin.clone()),
            time_of_minting: Some(1571797419),
            mint_run: None,
            serial_number: Some(3),
            quantity_minted_this_run: Some(3),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "0".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { mint_run_info, .. } => {
                assert_eq!(mint_run_info, Some(run_info_0));
            }
            _ => panic!("unexpected"),
        }
        let query_msg = QueryMsg::NftDossier {
            token_id: "1".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { mint_run_info, .. } => {
                assert_eq!(mint_run_info, Some(run_info_1));
            }
            _ => panic!("unexpected"),
        }
        let query_msg = QueryMsg::NftDossier {
            token_id: "2".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { mint_run_info, .. } => {
                assert_eq!(mint_run_info, Some(run_info_2));
            }
            _ => panic!("unexpected"),
        }

        // test mint_run_id
        let handle_msg = HandleMsg::MintNftClones {
            mint_run_id: Some("Starry Night".to_string()),
            quantity: 1,
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let run_info_3 = MintRunInfo {
            collection_creator: Some(instantiator.clone()),
            token_creator: Some(admin.clone()),
            time_of_minting: Some(1571797419),
            mint_run: Some(1),
            serial_number: Some(1),
            quantity_minted_this_run: Some(1),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "3".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { mint_run_info, .. } => {
                assert_eq!(mint_run_info, Some(run_info_3));
            }
            _ => panic!("unexpected"),
        }

        // test subsequent use of mint_run_id
        let handle_msg = HandleMsg::MintNftClones {
            mint_run_id: Some("Starry Night".to_string()),
            quantity: 2,
            owner: None,
            public_metadata: None,
            private_metadata: None,
            royalty_info: None,
            memo: None,
            padding: None,
        };
        let handle_result = handle(&mut deps, mock_env("admin", &[]), handle_msg);
        assert!(handle_result.is_ok());

        let run_info_4 = MintRunInfo {
            collection_creator: Some(instantiator.clone()),
            token_creator: Some(admin.clone()),
            time_of_minting: Some(1571797419),
            mint_run: Some(2),
            serial_number: Some(1),
            quantity_minted_this_run: Some(2),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "4".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { mint_run_info, .. } => {
                assert_eq!(mint_run_info, Some(run_info_4));
            }
            _ => panic!("unexpected"),
        }
        let run_info_5 = MintRunInfo {
            collection_creator: Some(instantiator.clone()),
            token_creator: Some(admin.clone()),
            time_of_minting: Some(1571797419),
            mint_run: Some(2),
            serial_number: Some(2),
            quantity_minted_this_run: Some(2),
        };
        let query_msg = QueryMsg::NftDossier {
            token_id: "5".to_string(),
            viewer: None,
            include_expired: None,
        };
        let query_result = query(&deps, query_msg);
        let query_answer: QueryAnswer = from_binary(&query_result.unwrap()).unwrap();
        match query_answer {
            QueryAnswer::NftDossier { mint_run_info, .. } => {
                assert_eq!(mint_run_info, Some(run_info_5));
            }
            _ => panic!("unexpected"),
        }
    }
}
