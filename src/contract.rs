/// This contract implements SNIP-721 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-721.md
use std::collections::HashSet;

use cosmwasm_std::{
    log, to_binary, Api, Binary, BlockInfo, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse,
    HandleResult, HumanAddr, InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage,
    StdError, StdResult, Storage, WasmMsg,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::utils::{pad_handle_result, pad_query_result};

use crate::expiration::Expiration;
use crate::msg::{
    AccessLevel, Burn, ContractStatus, Cw721Approval, Cw721OwnerOfResponse, HandleAnswer,
    HandleMsg, InitMsg, Mint, QueryAnswer, QueryMsg, ResponseStatus::Success, Send,
    Snip721Approval, Transfer, ViewerInfo,
};
use crate::rand::sha_256;
use crate::receiver::{batch_receive_nft_msg, receive_nft_msg};
use crate::state::{
    get_txs, json_may_load, json_save, load, may_load, remove, save, store_burn, store_mint,
    store_transfer, AuthList, Config, Permission, PermissionType, ReceiveRegistration, BLOCK_KEY,
    CONFIG_KEY, MINTERS_KEY, PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST, PREFIX_INFOS,
    PREFIX_MAP_TO_ID, PREFIX_MAP_TO_INDEX, PREFIX_OWNED, PREFIX_OWNER_PRIV, PREFIX_PRIV_META,
    PREFIX_PUB_META, PREFIX_RECEIVERS, PREFIX_TOKENS, PREFIX_VIEW_KEY, PRNG_SEED_KEY,
};
use crate::token::{Metadata, Token};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;
/// max number of token ids to keep in id list block
pub const ID_BLOCK_SIZE: u32 = 64;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the factory and creates a prng from the entropy String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    let admin = msg.admin.unwrap_or(env.message.sender);
    let admin_raw = deps.api.canonical_address(&admin)?;
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy).as_bytes()).to_vec();
    let init_config = msg.config.unwrap_or_default();

    let config = Config {
        name: msg.name,
        symbol: msg.symbol,
        admin: admin_raw.clone(),
        mint_cnt: 0,
        tx_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        token_supply_is_public: init_config.public_token_supply.unwrap_or(false),
        owner_is_public: init_config.public_owner.unwrap_or(false),
        sealed_metadata_is_enabled: init_config.enable_sealed_metadata.unwrap_or(false),
        unwrap_to_private: init_config.unwrapped_metadata_is_private.unwrap_or(false),
        minter_may_update_metadata: init_config.minter_may_update_metadata.unwrap_or(true),
        owner_may_update_metadata: init_config.owner_may_update_metadata.unwrap_or(false),
        burn_is_enabled: init_config.enable_burn.unwrap_or(false),
    };

    let minters = vec![admin_raw];
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    save(&mut deps.storage, MINTERS_KEY, &minters)?;
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    // TODO remove this after BlockInfo becomes available to queries
    save(&mut deps.storage, BLOCK_KEY, &env.block)?;

    // perform the post init callback if needed
    let messages: Vec<CosmosMsg> = if let Some(callback) = msg.post_init_callback {
        let execute = WasmMsg::Execute {
            msg: callback.msg,
            contract_addr: callback.contract_address,
            callback_code_hash: callback.code_hash,
            send: callback.send,
        };
        vec![execute.into()]
    } else {
        Vec::new()
    };
    Ok(InitResponse {
        messages,
        log: vec![],
    })
}

///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    // TODO remove this after BlockInfo becomes available to queries
    save(&mut deps.storage, BLOCK_KEY, &env.block)?;
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;

    let response = match msg {
        HandleMsg::MintNft {
            token_id,
            owner,
            public_metadata,
            private_metadata,
            memo,
            ..
        } => mint(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            token_id,
            owner,
            public_metadata,
            private_metadata,
            memo,
        ),
        HandleMsg::BatchMintNft { mut mints, .. } => batch_mint(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            &mut mints,
        ),
        HandleMsg::SetPublicMetadata {
            token_id, metadata, ..
        } => set_public_metadata(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &token_id,
            &metadata,
        ),
        HandleMsg::SetPrivateMetadata {
            token_id, metadata, ..
        } => set_private_metadata(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &token_id,
            &metadata,
        ),
        HandleMsg::Reveal { token_id, .. } => reveal(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &token_id,
        ),
        HandleMsg::MakeOwnershipPrivate { .. } => {
            make_owner_private(deps, env, &config, ContractStatus::StopTransactions.to_u8())
        }
        HandleMsg::SetGlobalApproval {
            token_id,
            view_owner,
            view_private_metadata,
            expires,
            ..
        } => set_global_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            token_id,
            view_owner,
            view_private_metadata,
            expires,
        ),
        HandleMsg::SetWhitelistedApproval {
            address,
            token_id,
            view_owner,
            view_private_metadata,
            transfer,
            expires,
            ..
        } => set_whitelisted_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &address,
            token_id,
            view_owner,
            view_private_metadata,
            transfer,
            expires,
            SetAppResp::SetWhitelistedApproval,
        ),
        HandleMsg::Approve {
            spender,
            token_id,
            expires,
            ..
        } => approve_revoke(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &spender,
            &token_id,
            expires,
            true,
        ),
        HandleMsg::Revoke {
            spender, token_id, ..
        } => approve_revoke(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &spender,
            &token_id,
            None,
            false,
        ),
        HandleMsg::ApproveAll {
            operator, expires, ..
        } => set_whitelisted_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &operator,
            None,
            None,
            None,
            Some(AccessLevel::All),
            expires,
            SetAppResp::ApproveAll,
        ),
        HandleMsg::RevokeAll { operator, .. } => set_whitelisted_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &operator,
            None,
            None,
            None,
            Some(AccessLevel::None),
            None,
            SetAppResp::RevokeAll,
        ),
        HandleMsg::TransferNft {
            recipient,
            token_id,
            memo,
            ..
        } => transfer_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            recipient,
            token_id,
            memo,
        ),
        HandleMsg::BatchTransferNft { transfers, .. } => batch_transfer_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            transfers,
        ),
        HandleMsg::SendNft {
            contract,
            token_id,
            msg,
            memo,
            ..
        } => send_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            contract,
            token_id,
            msg,
            memo,
        ),
        HandleMsg::BatchSendNft { sends, .. } => batch_send_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            sends,
        ),
        HandleMsg::RegisterReceiveNft {
            code_hash,
            also_implements_batch_receive_nft,
            ..
        } => register_receive_nft(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            code_hash,
            also_implements_batch_receive_nft,
        ),
        HandleMsg::BurnNft { token_id, memo, .. } => burn_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            token_id,
            memo,
        ),
        HandleMsg::BatchBurnNft { mut burns, .. } => batch_burn_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            &mut burns,
        ),
        HandleMsg::CreateViewingKey { entropy, .. } => create_key(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &entropy,
        ),
        HandleMsg::SetViewingKey { key, .. } => set_key(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            key,
        ),
        HandleMsg::AddMinters { minters, .. } => add_minters(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &minters,
        ),
        HandleMsg::RemoveMinters { minters, .. } => remove_minters(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &minters,
        ),
        HandleMsg::SetMinters { minters, .. } => set_minters(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &minters,
        ),
        HandleMsg::ChangeAdmin { address, .. } => change_admin(
            deps,
            env,
            &mut config,
            ContractStatus::StopTransactions.to_u8(),
            &address,
        ),
        HandleMsg::SetContractStatus { level, .. } => {
            set_contract_status(deps, env, &mut config, level)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// mint a new token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - optional token id, if not specified, use token index
/// * `owner` - optional owner of this token, if not specified, use the minter's address
/// * `public_metadata` - optional public metadata viewable by everyone
/// * `private_metadata` - optional private metadata viewable only by owner and whitelist
/// * `memo` - optional memo for the mint tx
#[allow(clippy::too_many_arguments)]
pub fn mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    token_id: Option<String>,
    owner: Option<HumanAddr>,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> =
        may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    let mut mints = vec![Mint {
        token_id,
        owner,
        public_metadata,
        private_metadata,
        memo,
    }];
    let mut minted = mint_list(deps, &env.block, config, &sender_raw, &mut mints)?;
    let minted_str = minted.pop().unwrap_or_else(String::new);
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("minted", &minted_str)],
        data: Some(to_binary(&HandleAnswer::MintNft {
            token_id: minted_str,
        })?),
    })
}

/// Returns HandleResult
///
/// mints many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `mints` - a mutable reference to the list of mints to perform
pub fn batch_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    mints: &mut Vec<Mint>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> =
        may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    let minted = mint_list(deps, &env.block, config, &sender_raw, mints)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("minted", format!("{:?}", &minted))],
        data: Some(to_binary(&HandleAnswer::BatchMintNft {
            token_ids: minted,
        })?),
    })
}

/// Returns HandleResult
///
/// sets new public metadata
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `metadata` - a reference to the new public metadata viewable by everyone
pub fn set_public_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: &str,
    metadata: &Metadata,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    set_metadata(
        &mut deps.storage,
        &sender_raw,
        token_id,
        PREFIX_PUB_META,
        metadata,
        config,
    )?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetPublicMetadata {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// sets new private metadata
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `metadata` - a reference to the new private metadata
pub fn set_private_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: &str,
    metadata: &Metadata,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    set_metadata(
        &mut deps.storage,
        &sender_raw,
        token_id,
        PREFIX_PRIV_META,
        metadata,
        config,
    )?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetPrivateMetadata {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// makes the sealed private metadata poublic
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
pub fn reveal<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: &str,
) -> HandleResult {
    check_status(config.status, priority)?;
    if !config.sealed_metadata_is_enabled {
        return Err(StdError::generic_err(
            "Sealed metadata functionality is not enabled for this contract",
        ));
    }
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let custom_err = format!("You do not own token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they do not own that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (mut token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    if token.unwrapped {
        return Err(StdError::generic_err(
            "This token has already been unwrapped",
        ));
    }
    if token.owner != sender_raw {
        return Err(StdError::generic_err(custom_err));
    }
    token.unwrapped = true;
    let token_key = idx.to_le_bytes();
    let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
    json_save(&mut info_store, &token_key, &token)?;
    if !config.unwrap_to_private {
        let mut priv_store = PrefixedStorage::new(PREFIX_PRIV_META, &mut deps.storage);
        let may_priv: Option<Metadata> = may_load(&priv_store, &token_key)?;
        if let Some(metadata) = may_priv {
            remove(&mut priv_store, &token_key);
            let mut pub_store = PrefixedStorage::new(PREFIX_PUB_META, &mut deps.storage);
            save(&mut pub_store, &token_key, &metadata)?;
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Reveal { status: Success })?),
    })
}

/// Returns HandleResult
///
/// grants/revokes trasfer permission on a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `spender` - a reference to the address being granted permission
/// * `token_id` - string slice of the token id to grant permission to
/// * `expires` - optional Expiration for this approval
/// * `is_approve` - true if this is an Approve call
#[allow(clippy::too_many_arguments)]
pub fn approve_revoke<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    spender: &HumanAddr,
    token_id: &str,
    expires: Option<Expiration>,
    is_approve: bool,
) -> HandleResult {
    check_status(config.status, priority)?;
    let address_raw = deps.api.canonical_address(spender)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let custom_err = format!(
        "Not authorized to grant/revoke transfer permission for token {}",
        token_id
    );
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    let mut all_perm: Option<Vec<Permission>> = None;
    let mut from_oper = false;
    let transfer_idx = PermissionType::Transfer.to_usize();
    // if not called by the owner, check if message sender has operator status
    if token.owner != sender_raw {
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let may_list: Option<Vec<Permission>> = json_may_load(&all_store, token.owner.as_slice())?;
        if let Some(list) = may_list.clone() {
            if let Some(perm) = list.iter().find(|&p| p.address == sender_raw) {
                if let Some(exp) = perm.expirations[transfer_idx] {
                    if exp.is_expired(&env.block) {
                        return Err(StdError::generic_err(format!(
                            "Transfer authority for all tokens of {} has expired",
                            &deps.api.human_address(&token.owner)?
                        )));
                    } else {
                        from_oper = true;
                    }
                }
            }
        }
        if !from_oper {
            return Err(StdError::generic_err(custom_err));
        }
        all_perm = may_list;
    }
    let mut accesses: [Option<AccessLevel>; 3] = [None, None, None];
    let response: HandleAnswer;
    if is_approve {
        accesses[transfer_idx] = Some(AccessLevel::ApproveToken);
        response = HandleAnswer::Approve { status: Success };
    } else {
        accesses[transfer_idx] = Some(AccessLevel::RevokeToken);
        response = HandleAnswer::Revoke { status: Success };
    }
    let owner = token.owner.clone();
    let mut proc_info = ProcessAccInfo {
        token,
        idx,
        token_given: true,
        accesses,
        expires,
        from_oper,
    };
    process_accesses(
        &mut deps.storage,
        &env,
        &address_raw,
        &owner,
        &mut proc_info,
        all_perm,
    )?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&response)?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// makes an address' token ownership private
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
pub fn make_owner_private<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    // only need to do this if the contract has public ownership
    if config.owner_is_public {
        let mut priv_store = PrefixedStorage::new(PREFIX_OWNER_PRIV, &mut deps.storage);
        save(&mut priv_store, sender_raw.as_slice(), &false)?
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::MakeOwnershipPrivate {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// adds/revokes access for everyone
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - optional token id to apply approvals to
/// * `view_owner` - optional access level for viewing token ownership
/// * `view_private_metadata` - optional access level for viewing private metadata
/// * `expires` - optional Expiration for this approval
#[allow(clippy::too_many_arguments)]
pub fn set_global_approval<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    token_id: Option<String>,
    view_owner: Option<AccessLevel>,
    view_private_metadata: Option<AccessLevel>,
    expires: Option<Expiration>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let token_given: bool;
    // use this "address" to represent global permission
    let global_raw = CanonicalAddr(Binary::from(b"public"));
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let mut custom_err = String::new();
    let (token, idx) = if let Some(id) = token_id {
        token_given = true;
        custom_err = format!("You do not own token {}", id);
        // if token supply is private, don't leak that the token id does not exist
        // instead just say they do not own that token
        let opt_err = if config.token_supply_is_public {
            None
        } else {
            Some(&*custom_err)
        };
        get_token(&deps.storage, &id, opt_err)?
    } else {
        token_given = false;
        (
            Token {
                owner: sender_raw.clone(),
                permissions: Vec::new(),
                unwrapped: false,
            },
            0,
        )
    };
    // if trying to set token permissions when you are not the owner
    if token_given && token.owner != sender_raw {
        return Err(StdError::generic_err(custom_err));
    }
    let mut accesses: [Option<AccessLevel>; 3] = [None, None, None];
    accesses[PermissionType::ViewOwner.to_usize()] = view_owner;
    accesses[PermissionType::ViewMetadata.to_usize()] = view_private_metadata;
    let mut proc_info = ProcessAccInfo {
        token,
        idx,
        token_given,
        accesses,
        expires,
        from_oper: false,
    };
    process_accesses(
        &mut deps.storage,
        &env,
        &global_raw,
        &sender_raw,
        &mut proc_info,
        None,
    )?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetGlobalApproval {
            status: Success,
        })?),
    })
}

/// Returns HandleResult
///
/// sets specified permissions for an address
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `address` - a reference to the address being granted permission
/// * `token_id` - optional token id to apply approvals to
/// * `view_owner` - optional access level for viewing token ownership
/// * `view_private_metadata` - optional access level for viewing private metadata
/// * `transfer` - optional access level for transferring tokens
/// * `expires` - optional Expiration for this approval
/// * `response_type` - which response to return for SetWhitelistedApproval, ApproveAll, or RevokeAll
#[allow(clippy::too_many_arguments)]
pub fn set_whitelisted_approval<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    address: &HumanAddr,
    token_id: Option<String>,
    view_owner: Option<AccessLevel>,
    view_private_metadata: Option<AccessLevel>,
    transfer: Option<AccessLevel>,
    expires: Option<Expiration>,
    response_type: SetAppResp,
) -> HandleResult {
    check_status(config.status, priority)?;
    let token_given: bool;
    let address_raw = deps.api.canonical_address(address)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let mut custom_err = String::new();
    let (token, idx) = if let Some(id) = token_id {
        token_given = true;
        custom_err = format!("You do not own token {}", id);
        // if token supply is private, don't leak that the token id does not exist
        // instead just say they do not own that token
        let opt_err = if config.token_supply_is_public {
            None
        } else {
            Some(&*custom_err)
        };
        get_token(&deps.storage, &id, opt_err)?
    } else {
        token_given = false;
        (
            Token {
                owner: sender_raw.clone(),
                permissions: Vec::new(),
                unwrapped: false,
            },
            0,
        )
    };
    // if trying to set token permissions when you are not the owner
    if token_given && token.owner != sender_raw {
        return Err(StdError::generic_err(custom_err));
    }
    let mut accesses: [Option<AccessLevel>; 3] = [None, None, None];
    accesses[PermissionType::ViewOwner.to_usize()] = view_owner;
    accesses[PermissionType::ViewMetadata.to_usize()] = view_private_metadata;
    accesses[PermissionType::Transfer.to_usize()] = transfer;
    let mut proc_info = ProcessAccInfo {
        token,
        idx,
        token_given,
        accesses,
        expires,
        from_oper: false,
    };
    process_accesses(
        &mut deps.storage,
        &env,
        &address_raw,
        &sender_raw,
        &mut proc_info,
        None,
    )?;
    let response = match response_type {
        SetAppResp::SetWhitelistedApproval => {
            HandleAnswer::SetWhitelistedApproval { status: Success }
        }
        SetAppResp::ApproveAll => HandleAnswer::ApproveAll { status: Success },
        SetAppResp::RevokeAll => HandleAnswer::RevokeAll { status: Success },
    };
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&response)?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// burns many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `burns` - a mutable reference to the list of burns to perform
pub fn batch_burn_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    burns: &mut Vec<Burn>,
) -> HandleResult {
    check_status(config.status, priority)?;
    if !config.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token",
        ));
    }
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    burn_list(deps, &env.block, config, &sender_raw, burns)?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchBurnNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// burns a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `token_id` - token id String of token to be burnt
/// * `memo` - optional memo for the burn tx
fn burn_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    token_id: String,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    if !config.burn_is_enabled {
        return Err(StdError::generic_err(
            "Burn functionality is not enabled for this token",
        ));
    }
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let mut burns = vec![Burn {
        token_ids: vec![token_id],
        memo,
    }];
    burn_list(deps, &env.block, config, &sender_raw, &mut burns)?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BurnNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// transfer many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `transfers` - list of transfers to perform
pub fn batch_transfer_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    transfers: Vec<Transfer>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let _m = send_list(deps, &env, config, &sender_raw, Some(transfers), None)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchTransferNft {
            status: Success,
        })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// transfer a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `recipient` - the address receiving the token
/// * `token_id` - token id String of token to be transferred
/// * `memo` - optional memo for the mint tx
pub fn transfer_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    recipient: HumanAddr,
    token_id: String,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let transfers = Some(vec![Transfer {
        recipient,
        token_ids: vec![token_id],
        memo,
    }]);
    let _m = send_list(deps, &env, config, &sender_raw, transfers, None)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TransferNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// sends tokens to contracts, and calls those contracts' ReceiveNft.  Will error if any
/// contract has not registered its ReceiveNft
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `sends` - list of SendNfts to perform
fn batch_send_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    sends: Vec<Send>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let messages = send_list(deps, &env, config, &sender_raw, None, Some(sends))?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchSendNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// sends a token to a contract, and calls that contract's ReceiveNft.  Will error if the
/// contract has not registered its ReceiveNft
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `contract` - the address of the contract receiving the token
/// * `token_id` - ID String of the token that was sent
/// * `msg` - optional msg used to control ReceiveNft logic
/// * `memo` - optional memo for the mint tx
#[allow(clippy::too_many_arguments)]
fn send_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    contract: HumanAddr,
    token_id: String,
    msg: Option<Binary>,
    memo: Option<String>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let sends = Some(vec![Send {
        contract,
        token_ids: vec![token_id],
        msg,
        memo,
    }]);
    let messages = send_list(deps, &env, config, &sender_raw, None, sends)?;

    let res = HandleResponse {
        messages,
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SendNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// registers a contract's ReceiveNft
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `code_hash` - code hash String of the registering contract
/// * `impl_batch` - optionally true if the contract also implements BatchReceiveNft
pub fn register_receive_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    code_hash: String,
    impl_batch: Option<bool>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let regrec = ReceiveRegistration {
        code_hash,
        impl_batch: impl_batch.unwrap_or(false),
    };
    let mut store = PrefixedStorage::new(PREFIX_RECEIVERS, &mut deps.storage);
    save(&mut store, sender_raw.as_slice(), &regrec)?;
    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RegisterReceiveNft {
            status: Success,
        })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `entropy` - string slice of the input String to be used as entropy in randomization
pub fn create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    entropy: &str,
) -> HandleResult {
    check_status(config.status, priority)?;
    let prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let key = ViewingKey::new(&env, &prng_seed, entropy.as_ref());
    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &key.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey {
            key: format!("{}", key),
        })?),
    })
}

/// Returns HandleResult
///
/// sets the viewing key to the input String
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `key` - String to be used as the viewing key
pub fn set_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    key: String,
) -> HandleResult {
    check_status(config.status, priority)?;
    let vk = ViewingKey(key.clone());
    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &vk.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey { key })?),
    })
}

/// Returns HandleResult
///
/// add a list of minters
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `new_minters` - list of minter addresses to add
pub fn add_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    new_minters: &[HumanAddr],
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let mut minters: Vec<CanonicalAddr> =
        may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
    let old_len = minters.len();
    for minter in new_minters {
        let minter_raw = deps.api.canonical_address(minter)?;
        if !minters.contains(&minter_raw) {
            minters.push(minter_raw);
        }
    }
    // only save if the list changed
    if old_len != minters.len() {
        save(&mut deps.storage, MINTERS_KEY, &minters)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::AddMinters { status: Success })?),
    })
}

/// Returns HandleResult
///
/// remove a list of minters
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `no_minters` - list of minter addresses to remove
pub fn remove_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    no_minters: &[HumanAddr],
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let may_minters: Option<Vec<CanonicalAddr>> = may_load(&deps.storage, MINTERS_KEY)?;
    if let Some(mut minters) = may_minters {
        let old_len = minters.len();
        let no_raw: Vec<CanonicalAddr> = no_minters
            .iter()
            .map(|x| deps.api.canonical_address(x))
            .collect::<StdResult<Vec<CanonicalAddr>>>()?;
        minters.retain(|m| !no_raw.contains(m));
        let new_len = minters.len();
        if new_len > 0 {
            if old_len != new_len {
                save(&mut deps.storage, MINTERS_KEY, &minters)?;
            }
        } else {
            remove(&mut deps.storage, MINTERS_KEY);
        }
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RemoveMinters { status: Success })?),
    })
}

/// Returns HandleResult
///
/// define the exact list of minters
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `human_minters` - exact list of minter addresses
pub fn set_minters<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    human_minters: &[HumanAddr],
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    // remove duplicates from the minters list
    let minters_raw: Vec<CanonicalAddr> = human_minters
        .iter()
        .map(|x| deps.api.canonical_address(x))
        .collect::<StdResult<Vec<CanonicalAddr>>>()?;
    let mut sortable: Vec<&[u8]> = minters_raw.iter().map(|x| x.as_slice()).collect();
    sortable.sort_unstable();
    sortable.dedup();
    let minters: Vec<CanonicalAddr> = sortable
        .iter()
        .map(|x| CanonicalAddr(Binary(x.to_vec())))
        .collect();
    if minters.is_empty() {
        remove(&mut deps.storage, MINTERS_KEY);
    } else {
        save(&mut deps.storage, MINTERS_KEY, &minters)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMinters { status: Success })?),
    })
}

/// Returns HandleResult
///
/// change the admin address
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `address` - new admin address
pub fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    address: &HumanAddr,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let new_admin = deps.api.canonical_address(address)?;
    if new_admin != config.admin {
        config.admin = new_admin;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

/// Returns HandleResult
///
/// set the contract status level
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `level` - new ContractStatus
pub fn set_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    level: ContractStatus,
) -> HandleResult {
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let new_status = level.to_u8();
    if config.status != new_status {
        config.status = new_status;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetContractStatus {
            status: Success,
        })?),
    })
}

/////////////////////////////////////// Query /////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::ContractInfo {} => query_contract_info(&deps.storage),
        QueryMsg::ContractConfig {} => query_config(&deps.storage),
        QueryMsg::Minters {} => query_minters(deps),
        QueryMsg::NumTokens { viewer } => query_num_tokens(deps, viewer),
        QueryMsg::AllTokens {
            viewer,
            start_after,
            limit,
        } => query_all_tokens(deps, viewer, start_after, limit),
        QueryMsg::OwnerOf {
            token_id,
            viewer,
            include_expired,
        } => query_owner_of(deps, &token_id, viewer, include_expired),
        QueryMsg::NftInfo { token_id } => query_nft_info(&deps.storage, &token_id),
        QueryMsg::PrivateMetadata { token_id, viewer } => {
            query_private_meta(deps, &token_id, viewer)
        }
        QueryMsg::AllNftInfo {
            token_id,
            viewer,
            include_expired,
        } => query_all_nft_info(deps, &token_id, viewer, include_expired),
        QueryMsg::NftDossier {
            token_id,
            viewer,
            include_expired,
        } => query_nft_dossier(deps, &token_id, viewer, include_expired),
        QueryMsg::TokenApprovals {
            token_id,
            viewing_key,
            include_expired,
        } => query_token_approvals(deps, &token_id, viewing_key, include_expired),
        QueryMsg::InventoryApprovals {
            address,
            viewing_key,
            include_expired,
        } => query_inventory_approvals(deps, &address, viewing_key, include_expired),
        QueryMsg::ApprovedForAll {
            owner,
            viewing_key,
            include_expired,
        } => query_approved_for_all(deps, &owner, viewing_key, include_expired),
        QueryMsg::Tokens {
            owner,
            viewer,
            viewing_key,
            start_after,
            limit,
        } => query_tokens(deps, &owner, viewer, viewing_key, start_after, limit),
        QueryMsg::VerifyTransferApproval {
            token_ids,
            address,
            viewing_key,
        } => query_verify_approval(deps, &token_ids, &address, viewing_key),
        QueryMsg::IsUnwrapped { token_id } => query_is_unwrapped(&deps.storage, &token_id),
        QueryMsg::TransactionHistory {
            address,
            viewing_key,
            page,
            page_size,
        } => query_transactions(deps, &address, viewing_key, page, page_size),
        QueryMsg::RegisteredCodeHash { contract } => query_code_hash(deps, &contract),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying the contract's name and symbol
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
pub fn query_contract_info<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;

    to_binary(&QueryAnswer::ContractInfo {
        name: config.name,
        symbol: config.symbol,
    })
}

/// Returns QueryResult displaying the contract's configuration
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
pub fn query_config<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;

    to_binary(&QueryAnswer::ContractConfig {
        token_supply_is_public: config.token_supply_is_public,
        owner_is_public: config.owner_is_public,
        sealed_metadata_is_enabled: config.sealed_metadata_is_enabled,
        unwrapped_metadata_is_private: config.unwrap_to_private,
        minter_may_update_metadata: config.minter_may_update_metadata,
        owner_may_update_metadata: config.owner_may_update_metadata,
        burn_is_enabled: config.burn_is_enabled,
    })
}

/// Returns QueryResult displaying the list of authorized minters
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
pub fn query_minters<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>) -> QueryResult {
    let minters: Vec<CanonicalAddr> =
        may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);

    to_binary(&QueryAnswer::Minters {
        minters: minters
            .iter()
            .map(|m| deps.api.human_address(m))
            .collect::<StdResult<Vec<HumanAddr>>>()?,
    })
}

/// Returns QueryResult displaying the number of tokens the contract controls
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
pub fn query_num_tokens<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
) -> QueryResult {
    // authenticate permission to view token supply
    check_view_supply(deps, viewer)?;
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let last_block = config.mint_cnt.saturating_sub(1) / ID_BLOCK_SIZE;
    let mut count = 0u32;
    let token_store = ReadonlyPrefixedStorage::new(PREFIX_TOKENS, &deps.storage);
    for i in 0..=last_block {
        let tokens: HashSet<String> =
            may_load(&token_store, &i.to_le_bytes())?.unwrap_or_else(HashSet::new);
        count += tokens.len() as u32;
    }
    to_binary(&QueryAnswer::NumTokens { count })
}

/// Returns QueryResult displaying the list of tokens that the contract controls
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `start_after` - optionally only display token ids that come after this String in
///                   lexicographical order
/// * `limit` - optional max number of tokens to display
pub fn query_all_tokens<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
    start_after: Option<String>,
    limit: Option<u32>,
) -> QueryResult {
    // authenticate permission to view token supply
    check_view_supply(deps, viewer)?;
    let after = start_after.unwrap_or_else(String::new);
    let size = limit.unwrap_or(300) as usize;
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let last_block = config.mint_cnt.saturating_sub(1) / ID_BLOCK_SIZE;
    let token_store = ReadonlyPrefixedStorage::new(PREFIX_TOKENS, &deps.storage);
    let mut tokens = Vec::new();
    for i in 0..=last_block {
        let token_list: HashSet<String> =
            may_load(&token_store, &i.to_le_bytes())?.unwrap_or_else(HashSet::new);
        for id in token_list {
            if id > after {
                tokens.push(id.to_string());
            }
        }
    }
    tokens.sort_unstable();
    tokens.truncate(size);
    to_binary(&QueryAnswer::TokenList { tokens })
}

/// Returns QueryResult displaying the owner of the input token if the requester is authorized
/// to view it and the transfer approvals on this token if the owner is querying
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewer` - optional address and key making an authenticated query request
/// * `include_expired` - optionally true if the Approval lists should include expired Approvals
pub fn query_owner_of<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewer: Option<ViewerInfo>,
    include_expired: Option<bool>,
) -> QueryResult {
    let (may_owner, approvals, _idx) =
        process_cw721_owner_of(deps, token_id, viewer, include_expired)?;
    if let Some(owner) = may_owner {
        return to_binary(&QueryAnswer::OwnerOf { owner, approvals });
    }
    Err(StdError::generic_err(format!(
        "You are not authorized to view the owner of token {}",
        token_id
    )))
}

/// Returns QueryResult displaying the public metadata of a token
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `token_id` - string slice of the token id
pub fn query_nft_info<S: ReadonlyStorage>(storage: &S, token_id: &str) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, storage);
    let may_idx: Option<u32> = may_load(&map2idx, token_id.as_bytes())?;
    // if token id was found
    if let Some(idx) = may_idx {
        let meta_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, storage);
        let meta: Metadata = may_load(&meta_store, &idx.to_le_bytes())?.unwrap_or(Metadata {
            name: None,
            description: None,
            image: None,
        });
        return to_binary(&QueryAnswer::NftInfo {
            name: meta.name,
            description: meta.description,
            image: meta.image,
        });
    }
    // token id wasn't found
    // if the token supply is public, let them know the token does not exist
    if config.token_supply_is_public {
        return Err(StdError::generic_err(format!(
            "Token ID: {} not found",
            token_id
        )));
    }
    // otherwise, just return empty metadata
    to_binary(&QueryAnswer::NftInfo {
        name: None,
        description: None,
        image: None,
    })
}

/// Returns QueryResult displaying the private metadata of a token if permitted to
/// view it
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewer` - optional address and key making an authenticated query request
pub fn query_private_meta<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewer: Option<ViewerInfo>,
) -> QueryResult {
    let prep_info = query_token_prep(deps, token_id, viewer)?;
    let opt_viewer = if prep_info.viewer_given {
        Some(&prep_info.viewer_raw)
    } else {
        None
    };
    check_perm_core(
        deps,
        &prep_info.block,
        &prep_info.token,
        token_id,
        opt_viewer,
        prep_info.token.owner.as_slice(),
        PermissionType::ViewMetadata.to_usize(),
        &mut Vec::new(),
        &prep_info.err_msg,
    )?;
    // don't display if private metadata is sealed
    if !prep_info.token.unwrapped {
        return Err(StdError::generic_err(
            "Sealed metadata must be unwrapped by calling Reveal before it can be viewed",
        ));
    }
    let meta_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    let meta: Metadata = may_load(&meta_store, &prep_info.idx.to_le_bytes())?.unwrap_or(Metadata {
        name: None,
        description: None,
        image: None,
    });
    to_binary(&QueryAnswer::PrivateMetadata {
        name: meta.name,
        description: meta.description,
        image: meta.image,
    })
}

/// Returns QueryResult displaying response of both the OwnerOf and NftInfo queries
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewer` - optional address and key making an authenticated query request
/// * `include_expired` - optionally true if the Approval lists should include expired Approvals
pub fn query_all_nft_info<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewer: Option<ViewerInfo>,
    include_expired: Option<bool>,
) -> QueryResult {
    let (owner, approvals, idx) = process_cw721_owner_of(deps, token_id, viewer, include_expired)?;
    let meta_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let info: Option<Metadata> = may_load(&meta_store, &idx.to_le_bytes())?;
    let access = Cw721OwnerOfResponse { owner, approvals };
    to_binary(&QueryAnswer::AllNftInfo { access, info })
}

/// Returns QueryResult displaying all the token information the querier is permitted to
/// view.  This may include the owner, the public metadata, the private metadata, and
/// the token and inventory approvals
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewer` - optional address and key making an authenticated query request
/// * `include_expired` - optionally true if the Approval lists should include expired Approvals
pub fn query_nft_dossier<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewer: Option<ViewerInfo>,
    include_expired: Option<bool>,
) -> QueryResult {
    let mut prep_info = query_token_prep(deps, token_id, viewer)?;
    let incl_exp = include_expired.unwrap_or(false);
    let owner_slice = prep_info.token.owner.as_slice();
    let opt_viewer = if prep_info.viewer_given {
        Some(&prep_info.viewer_raw)
    } else {
        None
    };
    let own_priv_store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
    let global_pass: bool =
        may_load(&own_priv_store, owner_slice)?.unwrap_or(prep_info.owner_is_public);
    let perm_type_info = PermissionTypeInfo {
        view_owner_idx: PermissionType::ViewOwner.to_usize(),
        view_meta_idx: PermissionType::ViewMetadata.to_usize(),
        transfer_idx: PermissionType::Transfer.to_usize(),
        num_types: PermissionType::Transfer.num_types(),
    };
    // get the owner if permitted
    let owner = if global_pass
        || check_perm_core(
            deps,
            &prep_info.block,
            &prep_info.token,
            token_id,
            opt_viewer,
            owner_slice,
            perm_type_info.view_owner_idx,
            &mut Vec::new(),
            &prep_info.err_msg,
        )
        .is_ok()
    {
        Some(deps.api.human_address(&prep_info.token.owner)?)
    } else {
        None
    };
    // get the public metadata
    let token_key = prep_info.idx.to_le_bytes();
    let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    let public_metadata: Option<Metadata> = may_load(&pub_store, &token_key)?;
    // get the private metadata if it is not sealed and if the viewer is permitted
    let mut display_private_metadata_error = None;
    let private_metadata = if let Err(err) = check_perm_core(
        deps,
        &prep_info.block,
        &prep_info.token,
        token_id,
        opt_viewer,
        owner_slice,
        perm_type_info.view_meta_idx,
        &mut Vec::new(),
        &prep_info.err_msg,
    ) {
        if let StdError::GenericErr { msg, .. } = err {
            display_private_metadata_error = Some(msg);
        }
        None
    } else if !prep_info.token.unwrapped {
        display_private_metadata_error = Some(
            "Sealed metadata must be unwrapped by calling Reveal before it can be viewed"
                .to_string(),
        );
        None
    } else {
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
        let priv_meta: Option<Metadata> = may_load(&priv_store, &token_key)?;
        priv_meta
    };
    // get the approvals
    let (token_approv, token_owner_exp, token_meta_exp) = gen_snip721_approvals(
        &deps.api,
        &prep_info.block,
        &mut prep_info.token.permissions,
        incl_exp,
        &perm_type_info,
    )?;
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let mut all_perm: Vec<Permission> =
        json_may_load(&all_store, owner_slice)?.unwrap_or_else(Vec::new);
    let (inventory_approv, all_owner_exp, all_meta_exp) = gen_snip721_approvals(
        &deps.api,
        &prep_info.block,
        &mut all_perm,
        incl_exp,
        &perm_type_info,
    )?;
    // determine if ownership is public
    let (public_ownership_expiration, owner_is_public) = if global_pass {
        (Some(Expiration::Never), true)
    } else if token_owner_exp.is_some() {
        (token_owner_exp, true)
    } else {
        (all_owner_exp, all_owner_exp.is_some())
    };
    // determine if private metadata is public
    let (private_metadata_is_public_expiration, private_metadata_is_public) =
        if token_meta_exp.is_some() {
            (token_meta_exp, true)
        } else {
            (all_meta_exp, all_meta_exp.is_some())
        };
    // if the viewer is the owner, display the approvals
    let (token_approvals, inventory_approvals) =
        if prep_info.viewer_given && prep_info.token.owner == prep_info.viewer_raw {
            (Some(token_approv), Some(inventory_approv))
        } else {
            (None, None)
        };
    to_binary(&QueryAnswer::NftDossier {
        owner,
        public_metadata,
        private_metadata,
        display_private_metadata_error,
        owner_is_public,
        public_ownership_expiration,
        private_metadata_is_public,
        private_metadata_is_public_expiration,
        token_approvals,
        inventory_approvals,
    })
}

/// Returns QueryResult displaying the approvals in place for a specified token
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewing_key` - the token owner's viewing key String
/// * `include_expired` - optionally true if the Approval lists should include expired Approvals
pub fn query_token_approvals<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewing_key: String,
    include_expired: Option<bool>,
) -> QueryResult {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let custom_err = format!(
        "You are not authorized to view approvals for token {}",
        token_id
    );
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (mut token, _idx) = get_token(&deps.storage, token_id, opt_err)?;
    check_key(&deps.storage, &token.owner, viewing_key)?;
    let owner_slice = token.owner.as_slice();
    let own_priv_store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
    let global_pass: bool =
        may_load(&own_priv_store, owner_slice)?.unwrap_or(config.owner_is_public);
    // TODO remove this when BlockInfo becomes available to queries
    let block: BlockInfo = may_load(&deps.storage, BLOCK_KEY)?.unwrap_or_else(|| BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    });
    let perm_type_info = PermissionTypeInfo {
        view_owner_idx: PermissionType::ViewOwner.to_usize(),
        view_meta_idx: PermissionType::ViewMetadata.to_usize(),
        transfer_idx: PermissionType::Transfer.to_usize(),
        num_types: PermissionType::Transfer.num_types(),
    };
    let incl_exp = include_expired.unwrap_or(false);
    let (token_approvals, token_owner_exp, token_meta_exp) = gen_snip721_approvals(
        &deps.api,
        &block,
        &mut token.permissions,
        incl_exp,
        &perm_type_info,
    )?;
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let mut all_perm: Vec<Permission> =
        json_may_load(&all_store, owner_slice)?.unwrap_or_else(Vec::new);
    let (_inventory_approv, all_owner_exp, all_meta_exp) =
        gen_snip721_approvals(&deps.api, &block, &mut all_perm, incl_exp, &perm_type_info)?;
    // determine if ownership is public
    let (public_ownership_expiration, owner_is_public) = if global_pass {
        (Some(Expiration::Never), true)
    } else if token_owner_exp.is_some() {
        (token_owner_exp, true)
    } else {
        (all_owner_exp, all_owner_exp.is_some())
    };
    // determine if private metadata is public
    let (private_metadata_is_public_expiration, private_metadata_is_public) =
        if token_meta_exp.is_some() {
            (token_meta_exp, true)
        } else {
            (all_meta_exp, all_meta_exp.is_some())
        };
    to_binary(&QueryAnswer::TokenApprovals {
        owner_is_public,
        public_ownership_expiration,
        private_metadata_is_public,
        private_metadata_is_public_expiration,
        token_approvals,
    })
}

/// Returns QueryResult displaying the inventory-wide approvals for a specified address
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `address` - a reference to the address whose approvals should be displayed
/// * `viewing_key` - the token owner's viewing key String
/// * `include_expired` - optionally true if the Approval lists should include expired Approvals
pub fn query_inventory_approvals<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: &HumanAddr,
    viewing_key: String,
    include_expired: Option<bool>,
) -> QueryResult {
    let owner_raw = deps.api.canonical_address(address)?;
    let owner_slice = owner_raw.as_slice();
    check_key(&deps.storage, &owner_raw, viewing_key)?;
    let own_priv_store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let global_pass: bool =
        may_load(&own_priv_store, owner_slice)?.unwrap_or(config.owner_is_public);
    // TODO remove this when BlockInfo becomes available to queries
    let block: BlockInfo = may_load(&deps.storage, BLOCK_KEY)?.unwrap_or_else(|| BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    });
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let mut all_perm: Vec<Permission> =
        json_may_load(&all_store, owner_slice)?.unwrap_or_else(Vec::new);
    let perm_type_info = PermissionTypeInfo {
        view_owner_idx: PermissionType::ViewOwner.to_usize(),
        view_meta_idx: PermissionType::ViewMetadata.to_usize(),
        transfer_idx: PermissionType::Transfer.to_usize(),
        num_types: PermissionType::Transfer.num_types(),
    };
    let (
        inventory_approvals,
        mut public_ownership_expiration,
        private_metadata_is_public_expiration,
    ) = gen_snip721_approvals(
        &deps.api,
        &block,
        &mut all_perm,
        include_expired.unwrap_or(false),
        &perm_type_info,
    )?;
    let owner_is_public = if global_pass {
        public_ownership_expiration = Some(Expiration::Never);
        true
    } else {
        public_ownership_expiration.is_some()
    };
    let private_metadata_is_public = private_metadata_is_public_expiration.is_some();
    to_binary(&QueryAnswer::InventoryApprovals {
        owner_is_public,
        public_ownership_expiration,
        private_metadata_is_public,
        private_metadata_is_public_expiration,
        inventory_approvals,
    })
}

/// Returns QueryResult displaying the list of all addresses that have approval to transfer
/// all of the owner's tokens.  Only the owner's viewing key will be accepted for this query
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `owner` - a reference to the address whose transfer ALL list should be displayed
/// * `viewing_key` - optional String of the owner's viewing key
/// * `include_expired` - optionally true if the Approval list should include expired Approvals
pub fn query_approved_for_all<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    owner: &HumanAddr,
    viewing_key: Option<String>,
    include_expired: Option<bool>,
) -> QueryResult {
    let owner_raw = deps.api.canonical_address(owner)?;
    if let Some(key) = viewing_key {
        check_key(&deps.storage, &owner_raw, key)?;
    } else {
        return to_binary(&QueryAnswer::ApprovedForAll {
            operators: Vec::new(),
        });
    }
    // TODO remove this when BlockInfo becomes available to queries
    let block: BlockInfo = may_load(&deps.storage, BLOCK_KEY)?.unwrap_or_else(|| BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    });
    let mut operators: Vec<Cw721Approval> = Vec::new();
    let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
    let all_perm: Vec<Permission> =
        json_may_load(&all_store, owner_raw.as_slice())?.unwrap_or_else(Vec::new);
    gen_cw721_approvals(
        &deps.api,
        &block,
        &all_perm,
        &mut operators,
        PermissionType::Transfer.to_usize(),
        include_expired.unwrap_or(false),
    )?;

    to_binary(&QueryAnswer::ApprovedForAll { operators })
}

/// Returns QueryResult displaying an optionally paginated list of all tokens belonging to
/// the owner address.  It will only display the tokens that the querier has view_owner
/// approval
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `owner` - a reference to the address whose tokens should be displayed
/// * `viewer` - optional address of the querier if different from the owner
/// * `viewing_key` - optional viewing key String
/// * `start_after` - optionally only display token ids that come after this String in
///                   lexicographical order
/// * `limit` - optional max number of tokens to display
pub fn query_tokens<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    owner: &HumanAddr,
    viewer: Option<HumanAddr>,
    viewing_key: Option<String>,
    start_after: Option<String>,
    limit: Option<u32>,
) -> QueryResult {
    let mut is_viewer = false;
    let mut is_owner = false;
    let owner_raw = deps.api.canonical_address(owner)?;
    let owner_slice = owner_raw.as_slice();
    let after = start_after.unwrap_or_else(String::new);
    let size = limit.unwrap_or(30) as usize;
    let (viewer_raw, vwr_given) = if let Some(vwr) = viewer {
        (deps.api.canonical_address(&vwr)?, true)
    } else {
        (CanonicalAddr(Binary::from(b"notused")), false)
    };
    // if we need to validate an address
    if let Some(key) = viewing_key {
        // if a viewer was supplied, they're saying they aren't the owner so check
        // if the key matches the viewer address first
        if vwr_given && check_key(&deps.storage, &viewer_raw, key.clone()).is_ok() {
            is_viewer = true;
        // check if this is the owner's key if we need to
        } else {
            check_key(&deps.storage, &owner_raw, key)?;
            is_owner = true;
        }
    }
    let querier = if is_viewer {
        Some(&viewer_raw)
    } else if is_owner {
        Some(&owner_raw)
    } else {
        None
    };
    // get list of owner's tokens
    let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
    let owned: HashSet<u32> = may_load(&owned_store, owner_slice)?.unwrap_or_else(HashSet::new);
    // if querier is different than the owner, check if ownership is public
    let mut known_pass = if !is_owner {
        let config: Config = load(&deps.storage, CONFIG_KEY)?;
        let own_priv_store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
        let pass: bool = may_load(&own_priv_store, owner_slice)?.unwrap_or(config.owner_is_public);
        pass
    } else {
        true
    };
    // TODO remove this when BlockInfo becomes available to queries
    let block = if !known_pass {
        let b: BlockInfo = may_load(&deps.storage, BLOCK_KEY)?.unwrap_or_else(|| BlockInfo {
            height: 1,
            time: 1,
            chain_id: "secret-2".to_string(),
        });
        b
    } else {
        BlockInfo {
            height: 1,
            time: 1,
            chain_id: "secret-2".to_string(),
        }
    };
    let exp_idx = PermissionType::ViewOwner.to_usize();
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, &deps.storage);
    let mut list_it: bool;
    let mut oper_for: Vec<CanonicalAddr> = Vec::new();
    let mut tokens: Vec<String> = Vec::new();
    let map2id = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_ID, &deps.storage);
    for idx in owned.iter() {
        let may_id: Option<String> = may_load(&map2id, &idx.to_le_bytes())?;
        if let Some(id) = may_id {
            // filter out ids before start_after
            if id > after {
                list_it = known_pass;
                // only check permissions if not public or owner
                if !known_pass {
                    let may_token: Option<Token> = json_may_load(&info_store, &idx.to_le_bytes())?;
                    if let Some(token) = may_token {
                        list_it = check_perm_core(
                            deps,
                            &block,
                            &token,
                            &id,
                            querier,
                            owner_slice,
                            exp_idx,
                            &mut oper_for,
                            "",
                        )
                        .is_ok();
                        // if querier is found to have ALL permission, no need to check permission ever again
                        if !oper_for.is_empty() {
                            known_pass = true;
                        }
                    }
                }
                if list_it {
                    tokens.push(id);
                }
            }
        }
    }
    tokens.sort_unstable();
    tokens.truncate(size);
    to_binary(&QueryAnswer::TokenList { tokens })
}

/// Returns QueryResult displaying true if the token has been unwrapped.  If sealed metadata
/// is not enabled, all tokens are considered unwrapped
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
pub fn query_is_unwrapped<S: ReadonlyStorage>(storage: &S, token_id: &str) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;
    let get_token_res = get_token(storage, token_id, None);
    match get_token_res {
        Err(err) => match err {
            // if the token id is not found, but token supply is private, just say
            // the token's wrapped state is the same as a newly minted token
            StdError::GenericErr { msg, .. }
                if !config.token_supply_is_public && msg.contains("Token ID") =>
            {
                to_binary(&QueryAnswer::IsUnwrapped {
                    token_is_unwrapped: !config.sealed_metadata_is_enabled,
                })
            }
            _ => Err(err),
        },
        Ok((token, _idx)) => to_binary(&QueryAnswer::IsUnwrapped {
            token_is_unwrapped: token.unwrapped,
        }),
    }
}

/// Returns QueryResult displaying an optionally paginated list of all transactions
/// involving a specified address, displayed in reverse chronological order
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `address` - a reference to the address whose transactions should be displayed
/// * `viewing_key` - viewing key String
/// * `page` - an optional page number.  If given, the most recent `page` times `page_size`
///            transactions will be skipped
/// * `page_size` - optional max number of transactions to display
pub fn query_transactions<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    address: &HumanAddr,
    viewing_key: String,
    page: Option<u32>,
    page_size: Option<u32>,
) -> StdResult<Binary> {
    let address_raw = deps.api.canonical_address(address)?;
    check_key(&deps.storage, &address_raw, viewing_key)?;
    let txs = get_txs(
        &deps.api,
        &deps.storage,
        &address_raw,
        page.unwrap_or(0),
        page_size.unwrap_or(30),
    )?;
    to_binary(&QueryAnswer::TransactionHistory { txs })
}

/// Returns QueryResult after verifying that the specified address has transfer approval
/// for all the listed tokens
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_ids` - a list of token ids to check if the address has transfer approval
/// * `address` - a reference to the address whose transactions should be displayed
/// * `viewing_key` - viewing key String
pub fn query_verify_approval<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_ids: &[String],
    address: &HumanAddr,
    viewing_key: String,
) -> StdResult<Binary> {
    let address_raw = deps.api.canonical_address(address)?;
    check_key(&deps.storage, &address_raw, viewing_key)?;
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    // TODO remove this when BlockInfo becomes available to queries
    let block: BlockInfo = may_load(&deps.storage, BLOCK_KEY)?.unwrap_or_else(|| BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    });
    let mut oper_for: Vec<CanonicalAddr> = Vec::new();
    for id in token_ids {
        if get_token_if_permitted(
            deps,
            &block,
            id,
            Some(&address_raw),
            PermissionType::Transfer,
            &mut oper_for,
            &config,
        )
        .is_err()
        {
            return to_binary(&QueryAnswer::VerifyTransferApproval {
                approved_for_all: false,
                first_unapproved_token: Some(id.to_string()),
            });
        }
    }
    to_binary(&QueryAnswer::VerifyTransferApproval {
        approved_for_all: true,
        first_unapproved_token: None,
    })
}

/// Returns QueryResult displaying the registered code hash of the specified contract if
/// it has registered and whether the contract implements BatchReceiveNft
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `contract` - a reference to the contract's address whose code hash is being requested
pub fn query_code_hash<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    contract: &HumanAddr,
) -> QueryResult {
    let contract_raw = deps.api.canonical_address(contract)?;
    let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, &deps.storage);
    let may_reg_rec: Option<ReceiveRegistration> = may_load(&store, contract_raw.as_slice())?;
    if let Some(reg_rec) = may_reg_rec {
        return to_binary(&QueryAnswer::RegisteredCodeHash {
            code_hash: Some(reg_rec.code_hash),
            also_implements_batch_receive_nft: reg_rec.impl_batch,
        });
    }
    to_binary(&QueryAnswer::RegisteredCodeHash {
        code_hash: None,
        also_implements_batch_receive_nft: false,
    })
}

// bundled info when prepping an authenticated token query
pub struct TokenQueryInfo {
    // querier's address
    viewer_raw: CanonicalAddr,
    // true if a viewer address was provided
    viewer_given: bool,
    // TODO remove this when BlockInfo becomes available to queries
    block: BlockInfo,
    // error message String
    err_msg: String,
    // the requested token
    token: Token,
    // the requested token's index
    idx: u32,
    // true if the contract has public ownership
    owner_is_public: bool,
}

/// Returns StdResult<TokenQueryInfo> after performing common preparations for authenticated
/// token queries
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewer` - optional address and key making an authenticated query request
fn query_token_prep<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewer: Option<ViewerInfo>,
) -> StdResult<TokenQueryInfo> {
    let (viewer_raw, viewer_given) = if let Some(vwr) = viewer {
        let viewer_raw = deps.api.canonical_address(&vwr.address)?;
        check_key(&deps.storage, &viewer_raw, vwr.viewing_key)?;
        (viewer_raw, true)
    } else {
        (CanonicalAddr(Binary::from(b"notused")), false)
    };
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    // TODO remove this when BlockInfo becomes available to queries
    let block: BlockInfo = may_load(&deps.storage, BLOCK_KEY)?.unwrap_or_else(|| BlockInfo {
        height: 1,
        time: 1,
        chain_id: "secret-2".to_string(),
    });
    let err_msg = format!(
        "You are not authorized to perform this action on token {}",
        token_id
    );
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*err_msg)
    };
    let (token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    Ok(TokenQueryInfo {
        viewer_raw,
        viewer_given,
        block,
        err_msg,
        token,
        idx,
        owner_is_public: config.owner_is_public,
    })
}

/// Returns StdResult<(Option<HumanAddr>, Vec<Cw721Approval>, u32)> which is the owner, list of transfer
/// approvals, and token index of the request token
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - string slice of the token id
/// * `viewer` - optional address and key making an authenticated query request
/// * `include_expired` - optionally true if the Approval lists should include expired Approvals
fn process_cw721_owner_of<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    token_id: &str,
    viewer: Option<ViewerInfo>,
    include_expired: Option<bool>,
) -> StdResult<(Option<HumanAddr>, Vec<Cw721Approval>, u32)> {
    let prep_info = query_token_prep(deps, token_id, viewer)?;
    let opt_viewer = if prep_info.viewer_given {
        Some(&prep_info.viewer_raw)
    } else {
        None
    };
    if check_permission(
        deps,
        &prep_info.block,
        &prep_info.token,
        token_id,
        opt_viewer,
        PermissionType::ViewOwner,
        &mut Vec::new(),
        &prep_info.err_msg,
        prep_info.owner_is_public,
    )
    .is_ok()
    {
        let (owner, mut approvals, mut operators) = get_owner_of_resp(
            deps,
            &prep_info.block,
            &prep_info.token,
            opt_viewer,
            include_expired.unwrap_or(false),
        )?;
        approvals.append(&mut operators);
        return Ok((Some(owner), approvals, prep_info.idx));
    }
    Ok((None, Vec::new(), prep_info.idx))
}

/// Returns StdResult<(HumanAddr, Vec<Cw721Approval>, Vec<Cw721Approval>)>
/// which is the owner, token transfer Approval list, and Approval list of everyone
/// that can transfer all of the token owner's tokens
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `token` - a reference to the token whose owner info is being requested
/// * `viewer` - optional reference to the address requesting to view the owner
/// * `include_expired` - true if the Approval lists should include expired Approvals
fn get_owner_of_resp<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block: &BlockInfo,
    token: &Token,
    viewer: Option<&CanonicalAddr>,
    include_expired: bool,
) -> StdResult<(HumanAddr, Vec<Cw721Approval>, Vec<Cw721Approval>)> {
    let owner = deps.api.human_address(&token.owner)?;
    let mut spenders: Vec<Cw721Approval> = Vec::new();
    let mut operators: Vec<Cw721Approval> = Vec::new();
    if let Some(vwr) = viewer {
        if token.owner == *vwr {
            let transfer_idx = PermissionType::Transfer.to_usize();
            gen_cw721_approvals(
                &deps.api,
                block,
                &token.permissions,
                &mut spenders,
                transfer_idx,
                include_expired,
            )?;
            let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
            let all_perm: Vec<Permission> =
                json_may_load(&all_store, token.owner.as_slice())?.unwrap_or_else(Vec::new);
            gen_cw721_approvals(
                &deps.api,
                block,
                &all_perm,
                &mut operators,
                transfer_idx,
                include_expired,
            )?;
        }
    }
    Ok((owner, spenders, operators))
}

/// Returns StdResult<()> resulting from generating the list of Approvals
///
/// # Arguments
///
/// * `api` - reference to the Api used to convert canonical and human addresses
/// * `block` - a reference to the current BlockInfo
/// * `perm_list` - slice of Permissions to search through looking for transfer approvals
/// * `approvals` - a mutable reference to the list of approvals that should be appended
///                 with any found in the permission list
/// * `transfer_idx` - index into the Permission expirations that represents transfers
/// * `include_expired` - true if the Approval list should include expired Approvals
fn gen_cw721_approvals<A: Api>(
    api: &A,
    block: &BlockInfo,
    perm_list: &[Permission],
    approvals: &mut Vec<Cw721Approval>,
    transfer_idx: usize,
    include_expired: bool,
) -> StdResult<()> {
    let global_raw = CanonicalAddr(Binary::from(b"public"));
    for perm in perm_list {
        if let Some(exp) = perm.expirations[transfer_idx] {
            if (include_expired || !exp.is_expired(block)) && perm.address != global_raw {
                approvals.push(Cw721Approval {
                    spender: api.human_address(&perm.address)?,
                    expires: exp,
                });
            }
        }
    }
    Ok(())
}

// permission type info
pub struct PermissionTypeInfo {
    // index for view owner permission
    pub view_owner_idx: usize,
    // index for view private metadata permission
    pub view_meta_idx: usize,
    // index for transfer permission
    pub transfer_idx: usize,
    // number of permission types
    pub num_types: usize,
}

/// Returns StdResult<(Vec<Snip721Approval>, Option<Expiration>, Option<Expiration>)>
/// which is the list of approvals, an optional Expiration if ownership is public, and
/// an optional Expiration if the private metadata is public
///
/// # Arguments
///
/// * `api` - reference to the Api used to convert canonical and human addresses
/// * `block` - a reference to the current BlockInfo
/// * `perm_list` - a mutable reference to the list of Permission
/// * `include_expired` - true if the Approval list should include expired Approvals
/// * `perm_type_info` - a reference to PermissionTypeInfo
fn gen_snip721_approvals<A: Api>(
    api: &A,
    block: &BlockInfo,
    perm_list: &mut Vec<Permission>,
    include_expired: bool,
    perm_type_info: &PermissionTypeInfo,
) -> StdResult<(Vec<Snip721Approval>, Option<Expiration>, Option<Expiration>)> {
    let global_raw = CanonicalAddr(Binary::from(b"public"));
    let mut approvals: Vec<Snip721Approval> = Vec::new();
    let mut owner_public: Option<Expiration> = None;
    let mut meta_public: Option<Expiration> = None;
    for perm in perm_list {
        // set global permissions if present
        if perm.address == global_raw {
            if let Some(exp) = perm.expirations[perm_type_info.view_owner_idx] {
                if !exp.is_expired(block) {
                    owner_public = Some(exp);
                }
            }
            if let Some(exp) = perm.expirations[perm_type_info.view_meta_idx] {
                if !exp.is_expired(block) {
                    meta_public = Some(exp);
                }
            }
        // otherwise create the approval summary
        } else {
            let mut has_some = false;
            for i in 0..perm_type_info.num_types {
                perm.expirations[i] =
                    perm.expirations[i].filter(|e| include_expired || !e.is_expired(block));
                if !has_some && perm.expirations[i].is_some() {
                    has_some = true;
                }
            }
            if has_some {
                approvals.push(Snip721Approval {
                    address: api.human_address(&perm.address)?,
                    view_owner_expiration: perm.expirations[perm_type_info.view_owner_idx].take(),
                    view_private_metadata_expiration: perm.expirations
                        [perm_type_info.view_meta_idx]
                        .take(),
                    transfer_expiration: perm.expirations[perm_type_info.transfer_idx].take(),
                });
            }
        }
    }
    Ok((approvals, owner_public, meta_public))
}

/// Returns StdResult<()>
///
/// returns Ok if authorized to view token supply, Err otherwise
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
fn check_view_supply<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
) -> StdResult<()> {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let mut is_auth = config.token_supply_is_public;
    if !is_auth {
        if let Some(vwr) = viewer {
            let viewer_raw = deps.api.canonical_address(&vwr.address)?;
            let minters: Vec<CanonicalAddr> =
                may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
            if minters.contains(&viewer_raw) {
                check_key(&deps.storage, &viewer_raw, vwr.viewing_key)?;
                is_auth = true;
            }
        }
        if !is_auth {
            return Err(StdError::generic_err(
                "The token supply of this contract is private",
            ));
        }
    }
    Ok(())
}

/// Returns StdResult<bool> result of validating an address' viewing key
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `address` - a reference to the address whose key should be validated
/// * `viewing_key` - String key used for authentication
fn check_key<S: ReadonlyStorage>(
    storage: &S,
    address: &CanonicalAddr,
    viewing_key: String,
) -> StdResult<()> {
    // load the address' key
    let read_key = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, storage);
    let load_key: [u8; VIEWING_KEY_SIZE] =
        may_load(&read_key, address.as_slice())?.unwrap_or_else(|| [0u8; VIEWING_KEY_SIZE]);
    let input_key = ViewingKey(viewing_key);
    // if key matches
    if input_key.check_viewing_key(&load_key) {
        return Ok(());
    }
    Err(StdError::generic_err(
        "Wrong viewing key for this address or viewing key not set",
    ))
}

/// Returns StdResult<()>
///
/// returns Ok if the address has permission or an error if not
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `token` - a reference to the token
/// * `token_id` - token ID String slice
/// * `opt_sender` - a optional reference to the address trying to get access to the token
/// * `perm_type` - PermissionType we are checking
/// * `oper_for` - a mutable reference to a list of owners that gave the sender "all" permission
/// * `custom_err` - string slice of the error msg to return if not permitted
/// * `owner_is_public` - true if token ownership is public for this contract
#[allow(clippy::too_many_arguments)]
pub fn check_permission<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block: &BlockInfo,
    token: &Token,
    token_id: &str,
    opt_sender: Option<&CanonicalAddr>,
    perm_type: PermissionType,
    oper_for: &mut Vec<CanonicalAddr>,
    custom_err: &str,
    owner_is_public: bool,
) -> StdResult<()> {
    let exp_idx = perm_type.to_usize();
    let owner_slice = token.owner.as_slice();
    // check if owner is public/private.  use owner's setting if present, contract default
    // if not
    if let PermissionType::ViewOwner = perm_type {
        let priv_store = ReadonlyPrefixedStorage::new(PREFIX_OWNER_PRIV, &deps.storage);
        let pass: bool = may_load(&priv_store, owner_slice)?.unwrap_or(owner_is_public);
        if pass {
            return Ok(());
        }
    }
    check_perm_core(
        deps,
        block,
        token,
        token_id,
        opt_sender,
        owner_slice,
        exp_idx,
        oper_for,
        custom_err,
    )
}

/// Returns StdResult<()>
///
/// returns Ok if the address has permission or an error if not
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `token` - a reference to the token
/// * `token_id` - token ID String slice
/// * `opt_sender` - a optional reference to the address trying to get access to the token
/// * `owner_slice` - the owner of the token represented as a byte slice
/// * `exp_idx` - permission type we are checking represented as usize
/// * `oper_for` - a mutable reference to a list of owners that gave the sender "all" permission
/// * `custom_err` - string slice of the error msg to return if not permitted
#[allow(clippy::too_many_arguments)]
fn check_perm_core<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block: &BlockInfo,
    token: &Token,
    token_id: &str,
    opt_sender: Option<&CanonicalAddr>,
    owner_slice: &[u8],
    exp_idx: usize,
    oper_for: &mut Vec<CanonicalAddr>,
    custom_err: &str,
) -> StdResult<()> {
    // if did not already pass with "all" permission for this owner
    if !oper_for.contains(&token.owner) {
        let mut err_msg = custom_err;
        let mut expired_msg = String::new();
        let global_raw = CanonicalAddr(Binary::from(b"public"));
        let sender = opt_sender.unwrap_or(&global_raw);
        // if this is the owner, all is good
        if token.owner == *sender {
            return Ok(());
        }
        // check if the token is public or the sender has token permission.
        // Can't use find because even if the global or sender permission expired, you
        // still want to see if the other is still valid
        let mut one_expired = false;
        let mut found_one = false;
        for perm in &token.permissions {
            if perm.address == *sender || perm.address == global_raw {
                if let Some(exp) = perm.expirations[exp_idx] {
                    if !exp.is_expired(block) {
                        return Ok(());
                    // if the permission is expired
                    } else {
                        // if this is the sender let them know the permission expired
                        if perm.address != global_raw {
                            expired_msg
                                .push_str(&format!("Access to token {} has expired", token_id));
                            err_msg = &expired_msg;
                        }
                        // if both were expired, there can't be any ALL permissions
                        // so just exit early
                        if one_expired {
                            return Err(StdError::generic_err(err_msg));
                        } else {
                            one_expired = true;
                        }
                    }
                }
                // we can quit if we found both the sender and the global
                if found_one {
                    break;
                } else {
                    found_one = true;
                }
            }
        }
        // check if the entire permission type is public or the sender has ALL permission.
        // Can't use find because even if the global or sender permission expired, you
        // still want to see if the other is still valid
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let may_list: Option<Vec<Permission>> = json_may_load(&all_store, owner_slice)?;
        found_one = false;
        if let Some(list) = may_list {
            for perm in &list {
                if perm.address == *sender || perm.address == global_raw {
                    if let Some(exp) = perm.expirations[exp_idx] {
                        if !exp.is_expired(block) {
                            oper_for.push(token.owner.clone());
                            return Ok(());
                        // if the permission expired
                        } else {
                            // if this is the sender let them know the permission expired
                            if perm.address != global_raw {
                                expired_msg.push_str(&format!(
                                    "Access to all tokens of {} has expired",
                                    &deps.api.human_address(&token.owner)?
                                ));
                                err_msg = &expired_msg;
                            }
                            // if both were expired, just exit early
                            if one_expired {
                                return Err(StdError::generic_err(err_msg));
                            } else {
                                one_expired = true;
                            }
                        }
                    }
                    // we can quit if we found both the sender and the global
                    if found_one {
                        return Err(StdError::generic_err(err_msg));
                    } else {
                        found_one = true;
                    }
                }
            }
        }
        return Err(StdError::generic_err(err_msg));
    }
    Ok(())
}

/// Returns StdResult<(Token, u32)>
///
/// returns the token information if the sender has authorization
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `token_id` - token ID String slice
/// * `sender` - a optional reference to the address trying to get access to the token
/// * `perm_type` - PermissionType we are checking
/// * `oper_for` - a mutable reference to a list of owners that gave the sender "all" permission
/// * `config` - a reference to the Config
fn get_token_if_permitted<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block: &BlockInfo,
    token_id: &str,
    sender: Option<&CanonicalAddr>,
    perm_type: PermissionType,
    oper_for: &mut Vec<CanonicalAddr>,
    config: &Config,
) -> StdResult<(Token, u32)> {
    let custom_err = format!(
        "You are not authorized to perform this action on token {}",
        token_id
    );
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(&deps.storage, token_id, opt_err)?;
    check_permission(
        deps,
        block,
        &token,
        token_id,
        sender,
        perm_type,
        oper_for,
        &custom_err,
        config.owner_is_public,
    )?;
    Ok((token, idx))
}

/// Returns StdResult<(Token, u32)>
///
/// returns the specified token and its identifier index
///
/// # Arguments
///
/// * `storage` - a reference to contract's storage
/// * `token_id` - token id string slice
/// * `custom_err` - optional custom error message to use if don't want to reveal that a token
///                  does not exist
fn get_token<S: ReadonlyStorage>(
    storage: &S,
    token_id: &str,
    custom_err: Option<&str>,
) -> StdResult<(Token, u32)> {
    let default_err: String;
    let not_found = if let Some(err) = custom_err {
        err
    } else {
        default_err = format!("Token ID: {} not found", token_id);
        &*default_err
    };
    let map2idx = ReadonlyPrefixedStorage::new(PREFIX_MAP_TO_INDEX, storage);
    let idx: u32 =
        may_load(&map2idx, token_id.as_bytes())?.ok_or_else(|| StdError::generic_err(not_found))?;
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, storage);
    let token: Token = json_may_load(&info_store, &idx.to_le_bytes())?.ok_or_else(|| {
        StdError::generic_err(format!("Unable to find token info for {}", token_id))
    })?;
    Ok((token, idx))
}

/// Returns StdResult<()> that will error if the priority level of the action is not
/// equal to or greater than the current contract status level
///
/// # Arguments
///
/// * `contract_status` - u8 representation of the current contract status
/// * `priority` - u8 representing the highest status level this action may execute at
fn check_status(contract_status: u8, priority: u8) -> StdResult<()> {
    if priority < contract_status {
        return Err(StdError::generic_err(
            "The contract admin has temporarily disabled this action",
        ));
    }
    Ok(())
}

/// Returns StdResult<()>
///
/// sets new metadata
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `sender` - a reference to the message sender address
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `prefix` - storage prefix for the type of metadata being updated
/// * `metadata` - a reference to the new metadata
/// * `config` - a reference to the Config
fn set_metadata<S: Storage>(
    storage: &mut S,
    sender: &CanonicalAddr,
    token_id: &str,
    prefix: &[u8],
    metadata: &Metadata,
    config: &Config,
) -> StdResult<()> {
    let custom_err = format!("Not authorized to update metadata of token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(storage, token_id, opt_err)?;
    // do not allow the altering of sealed metadata
    if !token.unwrapped && prefix == PREFIX_PRIV_META {
        return Err(StdError::generic_err(
            "The private metadata of a sealed token can not be modified",
        ));
    }
    if !(token.owner == *sender && config.owner_may_update_metadata) {
        let minters: Vec<CanonicalAddr> = may_load(storage, MINTERS_KEY)?.unwrap_or_else(Vec::new);
        if !(minters.contains(sender) && config.minter_may_update_metadata) {
            return Err(StdError::generic_err(custom_err));
        }
    }
    let mut meta_store = PrefixedStorage::new(prefix, storage);
    save(&mut meta_store, &idx.to_le_bytes(), metadata)?;
    Ok(())
}

// enum used to return correct response from SetWhitelistedApproval
pub enum SetAppResp {
    SetWhitelistedApproval,
    ApproveAll,
    RevokeAll,
}

// table of bools used to alter AuthLists properly
pub struct AlterAuthTable {
    // true if the specified token index should be added to an AuthList for that PermissionType
    pub add: [bool; 3],
    // true if all but the specified token index should be added to an AuthList for that PermType
    pub full: [bool; 3],
    // true if the specified token index should be removed from an AuthList for that PermType
    pub remove: [bool; 3],
    // true if the AuthList should be cleared for that Permission Type
    pub clear: [bool; 3],
    // true if there is at least one true in the table
    pub has_update: bool,
}

impl Default for AlterAuthTable {
    fn default() -> Self {
        AlterAuthTable {
            add: [false; 3],
            full: [false; 3],
            remove: [false; 3],
            clear: [false; 3],
            has_update: false,
        }
    }
}

// table of bools used to alter a permission list appropriately
pub struct AlterPermTable {
    // true if the address should be added to the permission list for that PermissionType
    pub add: [bool; 3],
    // true if the address should be removed from the permission list for that PermissionType
    pub remove: [bool; 3],
    // true if there is at least one true in the table
    pub has_update: bool,
}

impl Default for AlterPermTable {
    fn default() -> Self {
        AlterPermTable {
            add: [false; 3],
            remove: [false; 3],
            has_update: false,
        }
    }
}

// bundled info needed when setting accesses
pub struct ProcessAccInfo {
    // the input token or a default
    pub token: Token,
    // input token's mint index or a default
    pub idx: u32,
    // true if there was an input token
    pub token_given: bool,
    // the accesses being set
    pub accesses: [Option<AccessLevel>; 3],
    // optional expiration
    pub expires: Option<Expiration>,
    // true if this is an operator trying to set permissions
    pub from_oper: bool,
}

/// Returns StdResult<()>
///
/// sets specified permissions for an address
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `env` - a reference to the Env of the contract's environment
/// * `address` - a reference to the address being granted/revoked permission
/// * `owner` - a reference to the permission owner's address
/// * `proc_info` - a mutable reference to the ProcessAccInfo
/// * `all_perm_in` - when from an operator, the all_perms have already been read
fn process_accesses<S: Storage>(
    storage: &mut S,
    env: &Env,
    address: &CanonicalAddr,
    owner: &CanonicalAddr,
    proc_info: &mut ProcessAccInfo,
    all_perm_in: Option<Vec<Permission>>,
) -> StdResult<()> {
    let owner_slice = owner.as_slice();
    let expiration = proc_info.expires.unwrap_or_default();
    let expirations = vec![expiration; 3];
    let mut alt_all_perm = AlterPermTable::default();
    let mut alt_tok_perm = AlterPermTable::default();
    let mut alt_load_tok_perm = AlterPermTable::default();
    let mut alt_auth_list = AlterAuthTable::default();
    let mut add_load_list = Vec::new();
    let mut load_all = false;
    let mut load_all_exp = vec![Expiration::AtHeight(0); 3];
    let mut all_perm = if proc_info.from_oper {
        all_perm_in.ok_or_else(|| StdError::generic_err("Unable to get operator list"))?
    } else {
        Vec::new()
    };
    let mut oper_pos = 0usize;
    let mut found_perm = false;
    let mut tried_oper = false;
    let num_perm_types = PermissionType::ViewOwner.num_types();

    // do every permission type
    for i in 0..num_perm_types {
        if let Some(acc) = &proc_info.accesses[i] {
            match acc {
                AccessLevel::ApproveToken | AccessLevel::RevokeToken => {
                    if !proc_info.token_given {
                        return Err(StdError::generic_err(
                            "Attempted to grant/revoke permission for a token, but did not specify a token ID",
                        ));
                    }
                    let is_approve = matches!(acc, AccessLevel::ApproveToken);
                    // load the "all" permissions if we haven't already and see if the address is there
                    if !tried_oper {
                        if !proc_info.from_oper {
                            let all_store =
                                ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, storage);
                            all_perm =
                                json_may_load(&all_store, owner_slice)?.unwrap_or_else(Vec::new);
                        }
                        if let Some(pos) = all_perm.iter().position(|p| p.address == *address) {
                            found_perm = true;
                            oper_pos = pos;
                        }
                        tried_oper = true;
                    }
                    // if this address has "all" permission
                    if found_perm {
                        if let Some(op) = all_perm.get(oper_pos) {
                            if let Some(exp) = op.expirations[i] {
                                if !exp.is_expired(&env.block) {
                                    // don't allow one operator to change to another
                                    // operator's permissions
                                    if proc_info.from_oper {
                                        // if adding, don't do anything
                                        if is_approve {
                                            return Ok(());
                                        // if revoking, throw error
                                        } else {
                                            return Err(StdError::generic_err(
                                                "Can not revoke transfer permission from an existing operator",
                                            ));
                                        }
                                    }
                                    // if you are granting token approval to an existing
                                    // operator, but not changing the expiration, nothing
                                    // needs to be done
                                    if is_approve && expirations[i] == exp {
                                        return Ok(());
                                    }
                                    // need to put all the other tokens in the AuthList
                                    alt_auth_list.full[i] = true;
                                    // going to load all the other tokens
                                    load_all = true;
                                    // and use the "all" expiration as the token permission expirations
                                    load_all_exp[i] = exp;
                                    // add this address to all the other token permissions
                                    alt_load_tok_perm.add[i] = true;
                                    alt_load_tok_perm.has_update = true;
                                }
                                // remove "all" permission
                                alt_all_perm.remove[i] = true;
                                alt_all_perm.has_update = true;
                            }
                        }
                    }
                    if is_approve {
                        // add permission for this token
                        alt_tok_perm.add[i] = true;
                        // add this token to the authList
                        alt_auth_list.add[i] = true;
                    } else {
                        // revoke permission for this token
                        alt_tok_perm.remove[i] = true;
                        // remove this token from the AuthList
                        alt_auth_list.remove[i] = true;
                    }
                    alt_tok_perm.has_update = true;
                    alt_auth_list.has_update = true;
                }
                AccessLevel::All | AccessLevel::None => {
                    if let AccessLevel::All = acc {
                        // add "all" permission
                        alt_all_perm.add[i] = true;
                    } else {
                        // remove "all" permission
                        alt_all_perm.remove[i] = true;
                    }
                    alt_all_perm.has_update = true;
                    // clear the AuthList
                    alt_auth_list.clear[i] = true;
                    alt_auth_list.has_update = true;
                    // if a token was specified
                    if proc_info.token_given {
                        // also remove that token permission
                        alt_tok_perm.remove[i] = true;
                        alt_tok_perm.has_update = true;
                    }
                    // remove all other token permissions
                    alt_load_tok_perm.remove[i] = true;
                    alt_load_tok_perm.has_update = true;
                    // if not already going to load every owned token
                    if !load_all {
                        // load the AuthList tokens for this permission type
                        add_load_list.push(i);
                    }
                }
            }
        }
    }
    // update "all" permissions
    if alt_all_perm.has_update {
        // load "all" permissions if we haven't already
        if !tried_oper {
            let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, storage);
            all_perm = json_may_load(&all_store, owner_slice)?.unwrap_or_else(Vec::new);
        }
        // if there was an update to the "all" permissions
        if alter_perm_list(
            &mut all_perm,
            &alt_all_perm,
            address,
            &expirations,
            num_perm_types,
        ) {
            let mut all_store = PrefixedStorage::new(PREFIX_ALL_PERMISSIONS, storage);
            // if deleted last permitted address
            if all_perm.is_empty() {
                remove(&mut all_store, owner_slice);
            } else {
                json_save(&mut all_store, owner_slice, &all_perm)?;
            }
        }
    }
    // update input token permissions.
    // Shouldn't need to check if token was given because if it wasn't we would have thrown an
    // error before setting the has_update flag, but let's include the check anyway
    if alt_tok_perm.has_update && proc_info.token_given {
        // if there was an update to the token permissions
        if alter_perm_list(
            &mut proc_info.token.permissions,
            &alt_tok_perm,
            address,
            &expirations,
            num_perm_types,
        ) {
            let mut info_store = PrefixedStorage::new(PREFIX_INFOS, storage);
            json_save(
                &mut info_store,
                &proc_info.idx.to_le_bytes(),
                &proc_info.token,
            )?;
        }
    }
    // update the owner's AuthLists
    if alt_auth_list.has_update {
        // get the AuthLists for this address
        let auth_store = ReadonlyPrefixedStorage::new(PREFIX_AUTHLIST, storage);
        let mut auth_list: Vec<AuthList> =
            may_load(&auth_store, owner_slice)?.unwrap_or_else(Vec::new);
        let mut new_auth = AuthList {
            address: address.clone(),
            tokens: [Vec::new(), Vec::new(), Vec::new()],
        };
        let (auth, found, pos) =
            if let Some(pos) = auth_list.iter().position(|a| a.address == *address) {
                if let Some(a) = auth_list.get_mut(pos) {
                    (a, true, pos)
                // shouldn't ever find it but not successfully get it, so this should never happen
                } else {
                    (&mut new_auth, false, 0usize)
                }
            // didn't find the address in the permission list
            } else {
                (&mut new_auth, false, 0usize)
            };
        let mut load_list: HashSet<u32> = HashSet::new();
        // if we need to load other tokens create the load list
        if alt_load_tok_perm.has_update {
            // if we are loading all the owner's other tokens
            if load_all {
                let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, storage);
                let owned: HashSet<u32> =
                    may_load(&owned_store, owner_slice)?.unwrap_or_else(HashSet::new);
                load_list.extend(owned);
                // above, we already processed the input token, so remove it from the load list
                load_list.remove(&proc_info.idx);
            // just loading the tokens in the appropriate AuthList
            } else {
                for l in add_load_list {
                    load_list.extend(auth.tokens[l].iter());
                }
                // don't load the input token if given
                if proc_info.token_given {
                    load_list.remove(&proc_info.idx);
                }
            }
            let mut info_store = PrefixedStorage::new(PREFIX_INFOS, storage);
            for t_i in &load_list {
                let tok_key = t_i.to_le_bytes();
                let may_tok: Option<Token> = json_may_load(&info_store, &tok_key)?;
                if let Some(mut load_tok) = may_tok {
                    // shouldn't ever fail this ownership check, but let's be safe
                    if load_tok.owner == *owner
                        && alter_perm_list(
                            &mut load_tok.permissions,
                            &alt_load_tok_perm,
                            address,
                            &load_all_exp,
                            num_perm_types,
                        )
                    {
                        json_save(&mut info_store, &tok_key, &load_tok)?;
                    }
                }
            }
        }
        let mut updated = false;
        // do for each PermissionType
        for i in 0..num_perm_types {
            // if revoked all individual token permissions
            if alt_auth_list.clear[i] {
                if !auth.tokens[i].is_empty() {
                    auth.tokens[i].clear();
                    updated = true;
                }
            // else if gave permission to all individual tokens (except the input token)
            } else if alt_auth_list.full[i] {
                auth.tokens[i] = load_list.iter().copied().collect();
                // if this was an ApproveToken done to an address with ALL permission
                // also add the specified token
                if alt_auth_list.add[i] {
                    auth.tokens[i].push(proc_info.idx);
                }
                updated = true;
            // else if just adding the input token (shouldn't need the token_given check)
            } else if alt_auth_list.add[i] && proc_info.token_given {
                if !auth.tokens[i].contains(&proc_info.idx) {
                    auth.tokens[i].push(proc_info.idx);
                    updated = true;
                }
            // else if just revoking perm on the input token (don't need the token_given check)
            } else if alt_auth_list.remove[i] && proc_info.token_given {
                if let Some(tok_pos) = auth.tokens[i].iter().position(|&t| t == proc_info.idx) {
                    auth.tokens[i].swap_remove(tok_pos);
                    updated = true;
                }
            }
        }
        // if a change was made
        if updated {
            let mut auth_store = PrefixedStorage::new(PREFIX_AUTHLIST, storage);
            let mut save_it = true;
            // if the address has no authorized tokens
            if auth.tokens.iter().all(|t| t.is_empty()) {
                // and it was a pre-existing AuthList
                if found {
                    // if it was the only authorized address,
                    // remove the storage entry
                    if auth_list.len() == 1 {
                        remove(&mut auth_store, owner_slice);
                        save_it = false;
                    } else {
                        auth_list.swap_remove(pos);
                    }
                // address had no previous authorization so no need to add it
                } else {
                    save_it = false;
                }
            // AuthList has data, so save it
            } else {
                // if it is a new address, add it to the list
                if !found {
                    auth_list.push(new_auth);
                }
            }
            if save_it {
                save(&mut auth_store, owner_slice, &auth_list)?;
            }
        }
    }
    Ok(())
}

/// Returns bool
///
/// adds or removes permissions for an address based on the alterations table
///
/// # Arguments
///
/// * `perms` - a mutable reference to the list of permissions
/// * `alter_table` - a reference to the AlterPermTable to drive the Permission changes
/// * `address` - a reference to the address being added/revoked permission
/// * `expiration` - slice of Expirations for each PermissionType
/// * `num_perm_types` - the number of permission types
fn alter_perm_list(
    perms: &mut Vec<Permission>,
    alter_table: &AlterPermTable,
    address: &CanonicalAddr,
    expiration: &[Expiration],
    num_perm_types: usize,
) -> bool {
    let mut updated = false;
    let mut new_perm = Permission {
        address: address.clone(),
        expirations: [None; 3],
    };
    let (perm, found, pos) = if let Some(pos) = perms.iter().position(|p| p.address == *address) {
        if let Some(p) = perms.get_mut(pos) {
            (p, true, pos)
        // shouldn't ever find it but not successfully get it, so this should never happen
        } else {
            (&mut new_perm, false, 0usize)
        }
    // didn't find the address in the permission list
    } else {
        (&mut new_perm, false, 0usize)
    };
    // do for each PermissionType
    #[allow(clippy::needless_range_loop)]
    for i in 0..num_perm_types {
        // if supposed to add permission
        if alter_table.add[i] {
            // if it already has permission for this type
            if let Some(old_exp) = perm.expirations[i] {
                // if the new expiration is different
                if old_exp != expiration[i] {
                    perm.expirations[i] = Some(expiration[i]);
                    updated = true;
                }
            // new permission
            } else {
                perm.expirations[i] = Some(expiration[i]);
                updated = true;
            }
        // otherwise if we are supposed to remove permission
        } else if alter_table.remove[i] {
            // if it has permission for this type
            if perm.expirations[i].is_some() {
                // remove it
                perm.expirations[i] = None;
                updated = true;
            }
        }
    }
    // if a change was made
    if updated {
        // if this address had no permissions to start
        if !found {
            perms.push(new_perm);
        // if the last permission got revoked
        } else if perm.expirations.iter().all(|&e| e.is_none()) {
            perms.swap_remove(pos);
        }
    }
    updated
}

// a receiver, their code hash, and whether they implement BatchReceiveNft
pub struct ReceiverInfo {
    // the contract address
    pub contract: CanonicalAddr,
    // the contract's registration info
    pub registration: ReceiveRegistration,
}

/// Returns a StdResult<Vec<CosmosMsg>> list of ReceiveNft and BatchReceiveNft callacks that
/// should be done resulting from one Send
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `contract_human` - a reference to the human address of the contract receiving the tokens
/// * `contract` - a reference to the canonical address of the contract receiving the tokens
/// * `send_from_list` - list of SendFroms containing all the owners and their tokens being sent
/// * `msg` - a reference to the optional msg used to control ReceiveNft logic
/// * `sender` - a reference to the address that is sending the tokens
/// * `receivers` - a mutable reference the list of receiver contracts and their registration
///                 info
fn receiver_callback_msgs<S: ReadonlyStorage>(
    storage: &S,
    contract_human: &HumanAddr,
    contract: &CanonicalAddr,
    send_from_list: Vec<SendFrom>,
    msg: &Option<Binary>,
    sender: &HumanAddr,
    receivers: &mut Vec<ReceiverInfo>,
) -> StdResult<Vec<CosmosMsg>> {
    let (code_hash, impl_batch) =
        if let Some(receiver) = receivers.iter().find(|&r| r.contract == *contract) {
            (
                receiver.registration.code_hash.clone(),
                receiver.registration.impl_batch,
            )
        } else {
            let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, storage);
            let registration: ReceiveRegistration = may_load(&store, contract.as_slice())?
                .unwrap_or(ReceiveRegistration {
                    code_hash: String::new(),
                    impl_batch: false,
                });
            let receiver = ReceiverInfo {
                contract: contract.clone(),
                registration: registration.clone(),
            };
            receivers.push(receiver);
            (registration.code_hash, registration.impl_batch)
        };
    if code_hash.is_empty() {
        return Ok(Vec::new());
    }
    let mut callbacks: Vec<CosmosMsg> = Vec::new();
    for send_from in send_from_list.into_iter() {
        // if BatchReceiveNft is implemented, use it
        if impl_batch {
            callbacks.push(batch_receive_nft_msg(
                sender.clone(),
                send_from.owner,
                send_from.token_ids,
                msg.clone(),
                code_hash.clone(),
                contract_human.clone(),
            )?);
        //otherwise do a bunch of BatchReceiveNft
        } else {
            for token_id in send_from.token_ids.into_iter() {
                callbacks.push(receive_nft_msg(
                    send_from.owner.clone(),
                    token_id,
                    msg.clone(),
                    code_hash.clone(),
                    contract_human.clone(),
                )?);
            }
        }
    }
    Ok(callbacks)
}

// information about how an owner's token inventory has changed
pub struct InventoryUpdate {
    // token owner
    pub owner: CanonicalAddr,
    // the list of remaining tokens
    pub retain: HashSet<u32>,
    // the list of lost tokens
    pub remove: HashSet<u32>,
}

/// Returns StdResult<()>
///
/// update owners' inventories and AuthLists to reflect recent burns/transfers
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `updates` - a slice of an InventoryUpdate list to modify and store new inventories/AuthLists
/// * `num_perm_types` - the number of permission types
fn update_owner_inventory<S: Storage>(
    storage: &mut S,
    updates: &[InventoryUpdate],
    num_perm_types: usize,
) -> StdResult<()> {
    for update in updates {
        let owner_slice = update.owner.as_slice();
        // update the inventories
        let mut owned_store = PrefixedStorage::new(PREFIX_OWNED, storage);
        if update.retain.is_empty() {
            remove(&mut owned_store, owner_slice);
        } else {
            save(&mut owned_store, owner_slice, &update.retain)?;
        }
        // update the AuthLists if tokens were lost
        if !update.remove.is_empty() {
            let mut auth_store = PrefixedStorage::new(PREFIX_AUTHLIST, storage);
            let may_list: Option<Vec<AuthList>> = may_load(&auth_store, owner_slice)?;
            if let Some(mut list) = may_list {
                let mut new_list = Vec::new();
                for mut auth in list.drain(..) {
                    for i in 0..num_perm_types {
                        auth.tokens[i].retain(|t| !update.remove.contains(t));
                    }
                    if !auth.tokens.iter().all(|u| u.is_empty()) {
                        new_list.push(auth)
                    }
                }
                if new_list.is_empty() {
                    remove(&mut auth_store, owner_slice);
                } else {
                    save(&mut auth_store, owner_slice, &new_list)?;
                }
            }
        }
    }
    Ok(())
}

/// Returns StdResult<CanonicalAddr>
///
/// transfers a token, clears the token's permissions, and returns the previous owner's address
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `config` - a mutable reference to the Config
/// * `sender` - a reference to the message sender address
/// * `token_id` - token id String of token being transferred
/// * `recipient` - the recipient's address
/// * `oper_for` - a mutable reference to a list of owners that gave the sender "all" permission
/// * `inv_updates` - a mutable reference to the list of token inventories to update
/// * `memo` - optional memo for the transfer tx
#[allow(clippy::too_many_arguments)]
fn transfer_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    block: &BlockInfo,
    config: &mut Config,
    sender: &CanonicalAddr,
    token_id: String,
    recipient: CanonicalAddr,
    oper_for: &mut Vec<CanonicalAddr>,
    inv_updates: &mut Vec<InventoryUpdate>,
    memo: Option<String>,
) -> StdResult<CanonicalAddr> {
    let (mut token, idx) = get_token_if_permitted(
        deps,
        block,
        &token_id,
        Some(sender),
        PermissionType::Transfer,
        oper_for,
        &config,
    )?;
    let old_owner = token.owner;
    // don't bother processing anything if ownership does not change
    if old_owner == recipient {
        return Ok(old_owner);
    }
    token.owner = recipient.clone();
    token.permissions.clear();

    let update_addrs = vec![recipient.clone(), old_owner.clone()];
    // save updated token info
    let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
    json_save(&mut info_store, &idx.to_le_bytes(), &token)?;
    // log the inventory changes
    for addr in update_addrs.into_iter() {
        if let Some(inv) = inv_updates.iter_mut().find(|i| i.owner == addr) {
            // if updating the recipient's inventory
            if inv.owner == recipient {
                inv.retain.insert(idx);
            // otherwise updating the old owner's inventory
            } else {
                inv.retain.remove(&idx);
                inv.remove.insert(idx);
            }
        } else {
            let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
            let retain: HashSet<u32> =
                may_load(&owned_store, addr.as_slice())?.unwrap_or_else(HashSet::new);
            let mut new_inv = InventoryUpdate {
                owner: addr,
                retain,
                remove: HashSet::new(),
            };
            // if updating the recipient's inventory
            if new_inv.owner == recipient {
                new_inv.retain.insert(idx);
            // otherwise updating the old owner's inventory
            } else {
                new_inv.retain.remove(&idx);
                new_inv.remove.insert(idx);
            }
            inv_updates.push(new_inv);
        }
    }

    let sndr = if old_owner == *sender {
        None
    } else {
        Some(sender.clone())
    };
    // store the tx
    store_transfer(
        &mut deps.storage,
        config,
        block.height,
        token_id,
        old_owner.clone(),
        sndr,
        recipient,
        memo,
    )?;
    Ok(old_owner)
}

// list of tokens sent from one previous owner
pub struct SendFrom {
    // the owner's address
    pub owner: HumanAddr,
    // the tokens that were sent
    pub token_ids: Vec<String>,
}

/// Returns StdResult<Vec<CosmosMsg>>
///
/// transfer or sends a list of tokens and returns a list of ReceiveNft callbacks if applicable
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of the contract's environment
/// * `config` - a mutable reference to the Config
/// * `sender` - a reference to the message sender address
/// * `transfers` - optional list of transfers to perform
/// * `sends` - optional list of sends to perform
fn send_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: &Env,
    config: &mut Config,
    sender: &CanonicalAddr,
    transfers: Option<Vec<Transfer>>,
    sends: Option<Vec<Send>>,
) -> StdResult<Vec<CosmosMsg>> {
    let mut messages: Vec<CosmosMsg> = Vec::new();
    let mut oper_for: Vec<CanonicalAddr> = Vec::new();
    let mut inv_updates: Vec<InventoryUpdate> = Vec::new();
    let num_perm_types = PermissionType::ViewOwner.num_types();
    if let Some(mut xfers) = transfers {
        for xfer in xfers.drain(..) {
            let recipient_raw = deps.api.canonical_address(&xfer.recipient)?;
            for token_id in xfer.token_ids.into_iter() {
                let _o = transfer_impl(
                    deps,
                    &env.block,
                    config,
                    sender,
                    token_id,
                    recipient_raw.clone(),
                    &mut oper_for,
                    &mut inv_updates,
                    xfer.memo.clone(),
                )?;
            }
        }
    } else if let Some(mut snds) = sends {
        let mut receivers = Vec::new();
        for send in snds.drain(..) {
            let contract_raw = deps.api.canonical_address(&send.contract)?;
            let mut send_from_list: Vec<SendFrom> = Vec::new();
            for token_id in send.token_ids.into_iter() {
                let owner_raw = transfer_impl(
                    deps,
                    &env.block,
                    config,
                    sender,
                    token_id.clone(),
                    contract_raw.clone(),
                    &mut oper_for,
                    &mut inv_updates,
                    send.memo.clone(),
                )?;
                // compile list of all tokens being sent from each owner in this Send
                let owner = deps.api.human_address(&owner_raw)?;
                if let Some(sd_fm) = send_from_list.iter_mut().find(|s| s.owner == owner) {
                    sd_fm.token_ids.push(token_id.clone());
                } else {
                    let new_sd_fm = SendFrom {
                        owner,
                        token_ids: vec![token_id.clone()],
                    };
                    send_from_list.push(new_sd_fm);
                }
            }
            // get BatchReceiveNft and ReceiveNft msgs for all the tokens sent in this Send
            messages.extend(receiver_callback_msgs(
                &deps.storage,
                &send.contract,
                &contract_raw,
                send_from_list,
                &send.msg,
                &env.message.sender,
                &mut receivers,
            )?);
        }
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    update_owner_inventory(&mut deps.storage, &inv_updates, num_perm_types)?;
    Ok(messages)
}

// a block of token ids and its index
pub struct IdBlock {
    // block number
    pub index: u32,
    // token ids
    pub tokens: HashSet<String>,
}

/// Returns StdResult<()>
///
/// burns a list of tokens
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `config` - a mutable reference to the Config
/// * `sender` - a reference to the message sender address
/// * `burns` - list of burns to perform
fn burn_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    block: &BlockInfo,
    config: &mut Config,
    sender: &CanonicalAddr,
    burns: &mut Vec<Burn>,
) -> StdResult<()> {
    let mut oper_for: Vec<CanonicalAddr> = Vec::new();
    let mut inv_updates: Vec<InventoryUpdate> = Vec::new();
    let num_perm_types = PermissionType::ViewOwner.num_types();
    let mut id_blocks: Vec<IdBlock> = Vec::new();
    for burn in burns.drain(..) {
        for token_id in burn.token_ids.into_iter() {
            let (token, idx) = get_token_if_permitted(
                deps,
                block,
                &token_id,
                Some(sender),
                PermissionType::Transfer,
                &mut oper_for,
                &config,
            )?;
            // log the inventory change
            if let Some(inv) = inv_updates.iter_mut().find(|i| i.owner == token.owner) {
                inv.retain.remove(&idx);
                inv.remove.insert(idx);
            } else {
                let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
                let retain: HashSet<u32> =
                    may_load(&owned_store, token.owner.as_slice())?.unwrap_or_else(HashSet::new);
                let mut new_inv = InventoryUpdate {
                    owner: token.owner.clone(),
                    retain,
                    remove: HashSet::new(),
                };
                new_inv.retain.remove(&idx);
                new_inv.remove.insert(idx);
                inv_updates.push(new_inv);
            }
            let token_key = idx.to_le_bytes();
            // remove from block of token ids
            let this_block = idx / ID_BLOCK_SIZE;
            // if already burned a token in the same block
            if let Some(id_block) = id_blocks.iter_mut().find(|i| i.index == this_block) {
                id_block.tokens.remove(&token_id);
            // otherwise first time removing from this block
            } else {
                let token_store = ReadonlyPrefixedStorage::new(PREFIX_TOKENS, &deps.storage);
                let mut tokens =
                    may_load(&token_store, &this_block.to_le_bytes())?.unwrap_or_else(HashSet::new);
                tokens.remove(&token_id);
                id_blocks.push(IdBlock {
                    index: this_block,
                    tokens,
                });
            }
            // remove from maps
            let mut map2idx = PrefixedStorage::new(PREFIX_MAP_TO_INDEX, &mut deps.storage);
            remove(&mut map2idx, token_id.as_bytes());
            let mut map2id = PrefixedStorage::new(PREFIX_MAP_TO_ID, &mut deps.storage);
            remove(&mut map2id, &token_key);
            // remove the token info
            let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
            remove(&mut info_store, &token_key);
            // remove metadata if existent
            let mut pub_store = PrefixedStorage::new(PREFIX_PUB_META, &mut deps.storage);
            remove(&mut pub_store, &token_key);
            let mut priv_store = PrefixedStorage::new(PREFIX_PRIV_META, &mut deps.storage);
            remove(&mut priv_store, &token_key);
            let brnr = if token.owner == *sender {
                None
            } else {
                Some(sender.clone())
            };
            // store the tx
            store_burn(
                &mut deps.storage,
                config,
                block.height,
                token_id,
                token.owner,
                brnr,
                burn.memo.clone(),
            )?;
        }
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    let mut token_store = PrefixedStorage::new(PREFIX_TOKENS, &mut deps.storage);
    for id_block in id_blocks.iter() {
        save(
            &mut token_store,
            &id_block.index.to_le_bytes(),
            &id_block.tokens,
        )?;
    }
    update_owner_inventory(&mut deps.storage, &inv_updates, num_perm_types)?;
    Ok(())
}

// an owner and their list of tokens
pub struct Inventory {
    // the owner's address
    pub owner: CanonicalAddr,
    // the owner's tokens
    pub tokens: HashSet<u32>,
}

/// Returns <Vec<String>>
///
/// mints a list of new tokens and returns the ids of the tokens minted
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `block` - a reference to the current BlockInfo
/// * `config` - a mutable reference to the Config
/// * `sender_raw` - a reference to the message sender address
/// * `mints` - list of mints to perform
fn mint_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    block: &BlockInfo,
    config: &mut Config,
    sender_raw: &CanonicalAddr,
    mints: &mut Vec<Mint>,
) -> StdResult<Vec<String>> {
    let mut inventories: Vec<Inventory> = Vec::new();
    let mut minted: Vec<String> = Vec::new();
    let mut old_block = u64::MAX;
    let mut tokens: HashSet<String> = HashSet::new();
    let save_tokens = !mints.is_empty();
    for mint in mints.drain(..) {
        let id = mint.token_id.unwrap_or(format!("{}", config.mint_cnt));
        // check if id already exists
        let mut map2idx = PrefixedStorage::new(PREFIX_MAP_TO_INDEX, &mut deps.storage);
        let may_exist: Option<u32> = may_load(&map2idx, id.as_bytes())?;
        if may_exist.is_some() {
            return Err(StdError::generic_err(format!(
                "Token ID {} is already in use",
                id
            )));
        }
        // map new token id to its index
        save(&mut map2idx, id.as_bytes(), &config.mint_cnt)?;
        let recipient = if let Some(o) = mint.owner {
            deps.api.canonical_address(&o)?
        } else {
            sender_raw.clone()
        };

        // if you are modifying the base contract to include other data fields on-chain in
        // the Token struct (see token.rs), this is where you may populate those additional
        // fields.  Conversely, you could also store the additional fields as a struct with
        // its own storage prefix, similar to how the metadata is handled below

        let token = Token {
            owner: recipient.clone(),
            permissions: Vec::new(),
            unwrapped: !config.sealed_metadata_is_enabled,
        };
        //
        //

        // save new token info
        let token_key = config.mint_cnt.to_le_bytes();
        let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
        json_save(&mut info_store, &token_key, &token)?;
        // add token to owner's list
        let mut new_inv = Inventory {
            owner: token.owner.clone(),
            tokens: HashSet::new(),
        };
        let (inventory, found) =
            if let Some(inv) = inventories.iter_mut().find(|i| i.owner == new_inv.owner) {
                (inv, true)
            } else {
                let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
                new_inv.tokens =
                    may_load(&owned_store, new_inv.owner.as_slice())?.unwrap_or_else(HashSet::new);
                (&mut new_inv, false)
            };
        inventory.tokens.insert(config.mint_cnt);
        if !found {
            inventories.push(new_inv);
        }
        // add to block of token ids
        let this_block = config.mint_cnt / ID_BLOCK_SIZE;
        // if first in mint list or filled last block
        if this_block as u64 != old_block {
            let mut token_store = PrefixedStorage::new(PREFIX_TOKENS, &mut deps.storage);
            // if first in mint list, just load the block
            if old_block == u64::MAX {
                tokens =
                    may_load(&token_store, &this_block.to_le_bytes())?.unwrap_or_else(HashSet::new);
            // else filled last block so save it
            } else {
                save(&mut token_store, &(old_block as u32).to_le_bytes(), &tokens)?;
                tokens.clear();
            }
        }
        // add new token id
        tokens.insert(id.clone());
        old_block = this_block as u64;
        // map index to id
        let mut map2id = PrefixedStorage::new(PREFIX_MAP_TO_ID, &mut deps.storage);
        save(&mut map2id, &token_key, &id)?;

        //
        // If you wanted to store an additional data struct for each NFT, you would create
        // a new prefix and store with the `token_key` like below
        //
        // save the metadata
        if let Some(pub_meta) = mint.public_metadata {
            let mut pub_store = PrefixedStorage::new(PREFIX_PUB_META, &mut deps.storage);
            save(&mut pub_store, &token_key, &pub_meta)?;
        }
        if let Some(priv_meta) = mint.private_metadata {
            let mut priv_store = PrefixedStorage::new(PREFIX_PRIV_META, &mut deps.storage);
            save(&mut priv_store, &token_key, &priv_meta)?;
        }
        //
        //

        // store the tx
        store_mint(
            &mut deps.storage,
            config,
            block.height,
            id.clone(),
            sender_raw.clone(),
            recipient,
            mint.memo,
        )?;
        minted.push(id);
        // increment index for next mint
        config.mint_cnt += 1;
    }
    // save all the updated owners' token lists
    let mut owned_store = PrefixedStorage::new(PREFIX_OWNED, &mut deps.storage);
    for inventory in inventories {
        save(
            &mut owned_store,
            inventory.owner.as_slice(),
            &inventory.tokens,
        )?;
    }
    if save_tokens {
        let mut token_store = PrefixedStorage::new(PREFIX_TOKENS, &mut deps.storage);
        save(&mut token_store, &(old_block as u32).to_le_bytes(), &tokens)?;
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    Ok(minted)
}
