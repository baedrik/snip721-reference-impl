/// This contract implements SNIP-721 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-721.md
use std::collections::{HashMap, HashSet};

use cosmwasm_std::{
    log, to_binary, Api, Binary, BlockInfo, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse,
    HandleResult, HumanAddr, InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage,
    StdError, StdResult, Storage, Uint128,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::utils::{pad_handle_result, pad_query_result, HandleCallback};

use crate::expiration::Expiration;
use crate::msg::{
    Access, Burn, ContractStatus, HandleAnswer, HandleMsg, InitMsg, QueryAnswer, QueryMsg,
    ResponseStatus::Success, Send, Transfer,
};
use crate::rand::sha_256;
use crate::receiver::receive_nft_msg;
use crate::state::{
    get_txs, json_load, json_may_load, json_save, load, may_load, remove, save, store_burn,
    store_mint, store_transfer, AuthList, Config, Permission, PermissionType, CONFIG_KEY,
    MINTERS_KEY, PREFIX_ALL_PERMISSIONS, PREFIX_AUTHLIST, PREFIX_INFOS, PREFIX_OWNED,
    PREFIX_PRIV_META, PREFIX_PUB_META, PREFIX_RECEIVERS, PREFIX_VIEW_KEY, PRNG_SEED_KEY,
    TOKENS_KEY,
};
use crate::token::{Metadata, Token};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;

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
    let tokens: HashMap<String, u32> = HashMap::new();
    let admin = msg.admin.unwrap_or(env.message.sender);
    let admin_raw = deps.api.canonical_address(&admin)?;
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy).as_bytes()).to_vec();
    let init_config = msg.config.unwrap_or_default();
    // if sealed is enabled, private metadata must be enabled, because it uses the private metadata
    let sealed_enabled = init_config.enable_sealed_metadata.unwrap_or(false);
    let private_enabled = init_config.enable_private_metadata.unwrap_or(true) || sealed_enabled;

    let config = Config {
        name: msg.name,
        symbol: msg.symbol,
        admin: admin_raw.clone(),
        mint_cnt: 0,
        tx_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        token_supply_is_public: init_config.public_token_supply.unwrap_or(false),
        owner_is_public: init_config.public_owner.unwrap_or(false),
        private_metadata_is_enabled: private_enabled,
        sealed_metadata_is_enabled: sealed_enabled,
        unwrap_to_private: init_config.unwrapped_metadata_is_private.unwrap_or(false),
        minter_may_update_metadata: init_config.minter_may_update_metadata.unwrap_or(true),
        owner_may_update_metadata: init_config.owner_may_update_metadata.unwrap_or(false),
        burn_is_enabled: init_config.enable_burn.unwrap_or(false),
    };

    let minters = vec![admin_raw];
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    save(&mut deps.storage, TOKENS_KEY, &tokens)?;
    save(&mut deps.storage, MINTERS_KEY, &minters)?;
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;

    Ok(InitResponse::default())
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
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;

    let response = match msg {
        HandleMsg::Mint {
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
        HandleMsg::SetApproval {
            address,
            token_id,
            view_owner,
            view_private_metadata,
            transfer,
            expires,
            ..
        } => set_approval(
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
            SetAppResp::SetApproval,
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
        } => set_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &operator,
            None,
            None,
            None,
            Some(Access::All),
            expires,
            SetAppResp::ApproveAll,
        ),
        HandleMsg::RevokeAll { operator, .. } => set_approval(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &operator,
            None,
            None,
            None,
            Some(Access::None),
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
        HandleMsg::RegisterReceiveNft { code_hash, .. } => register_receive_nft(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            code_hash,
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
        may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(|| Vec::new());
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    if !config.private_metadata_is_enabled && private_metadata.is_some() {
        return Err(StdError::generic_err(
            "Private metadata functionality is not enabled for this contract",
        ));
    }
    let mut tokens: HashMap<String, u32> =
        may_load(&deps.storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
    let id = token_id.unwrap_or(format!("{}", config.mint_cnt));
    if tokens.contains_key(&id) {
        return Err(StdError::generic_err("Token ID is already in use"));
    }
    let recipient = if let Some(o) = owner {
        deps.api.canonical_address(&o)?
    } else {
        sender_raw.clone()
    };
    // add token to owner's list
    let owner_slice = recipient.as_slice();
    let mut owned_store = PrefixedStorage::new(PREFIX_OWNED, &mut deps.storage);
    let mut owned: HashSet<u32> =
        may_load(&owned_store, owner_slice)?.unwrap_or_else(|| HashSet::new());
    owned.insert(config.mint_cnt);
    save(&mut owned_store, owner_slice, &owned)?;

    let token = Token {
        owner: recipient.clone(),
        permissions: Vec::new(),
        unwrapped: false,
    };
    // save new token info
    let token_key = config.mint_cnt.to_le_bytes();
    let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
    json_save(&mut info_store, &token_key, &token)?;
    // add to token list
    tokens.insert(id.clone(), config.mint_cnt);
    save(&mut deps.storage, TOKENS_KEY, &tokens)?;
    // save the metadata
    if let Some(pub_meta) = public_metadata {
        let mut pub_store = PrefixedStorage::new(PREFIX_PUB_META, &mut deps.storage);
        save(&mut pub_store, &token_key, &pub_meta)?;
    }
    if let Some(priv_meta) = private_metadata {
        let mut priv_store = PrefixedStorage::new(PREFIX_PRIV_META, &mut deps.storage);
        save(&mut priv_store, &token_key, &priv_meta)?;
    }
    // store the tx
    store_mint(
        &mut deps.storage,
        config,
        env.block.height,
        id,
        sender_raw,
        recipient,
        memo,
    )?;
    // increment index for next mint
    config.mint_cnt += 1;
    save(&mut deps.storage, CONFIG_KEY, &config)?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::Mint { status: Success })?),
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
    if !config.private_metadata_is_enabled {
        return Err(StdError::generic_err(
            "Private metadata functionality is not enabled for this contract",
        ));
    }
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
    let tokens: HashMap<String, u32> =
        may_load(&deps.storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
    let custom_err = format!("You do not own token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they do not own that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (mut token, idx) = get_token(&deps.storage, token_id, &tokens, opt_err)?;
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
    let tokens: HashMap<String, u32> =
        may_load(&deps.storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
    let custom_err = format!("Not authorized to grant/revoke transfer permission for token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(&deps.storage, token_id, &tokens, opt_err)?;
    let mut all_perm: Option<Vec<Permission>> = None;
    let mut from_oper = false;
    // if not called by the owner, check if message sender has operator status
    if token.owner != sender_raw {
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let may_list: Option<Vec<Permission>> = json_may_load(&all_store, token.owner.as_slice())?;
        if let Some(list) = may_list.clone() {
            if let Some(perm) = list.iter().find(|&p| p.address == sender_raw) {
                if let Some(exp) = perm.expirations[PermissionType::Transfer.to_u8() as usize] {
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
    let mut accesses: [Option<Access>; 3] = [None, None, None];
    let response: HandleAnswer;
    if is_approve {
        accesses[PermissionType::Transfer.to_u8() as usize] = Some(Access::ApproveToken);
        response = HandleAnswer::Approve { status: Success };
    } else {
        accesses[PermissionType::Transfer.to_u8() as usize] = Some(Access::RevokeToken);
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
/// * `response_type` - which response to return for SetApproval, ApproveAll, or RevokeAll
pub fn set_approval<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    address: &HumanAddr,
    token_id: Option<String>,
    view_owner: Option<Access>,
    view_private_metadata: Option<Access>,
    transfer: Option<Access>,
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
        let tokens: HashMap<String, u32> =
            may_load(&deps.storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
        custom_err = format!("You do not own token {}", id);
        // if token supply is private, don't leak that the token id does not exist
        // instead just say they do not own that token
        let opt_err = if config.token_supply_is_public {
            None
        } else {
            Some(&*custom_err)
        };
        get_token(&deps.storage, &id, &tokens, opt_err)?
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
    // if trying to set view private metadata permission when private metadata is disabled
    if view_private_metadata.is_some() && !config.private_metadata_is_enabled {
        return Err(StdError::generic_err(
            "Private metadata functionality is not enabled for this contract",
        ));
    }
    let mut accesses: [Option<Access>; 3] = [None, None, None];
    accesses[PermissionType::ViewOwner.to_u8() as usize] = view_owner;
    accesses[PermissionType::ViewMetadata.to_u8() as usize] = view_private_metadata;
    accesses[PermissionType::Transfer.to_u8() as usize] = transfer;
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
        SetAppResp::SetApproval => HandleAnswer::SetApproval { status: Success },
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
    let mut burns = vec![Burn { token_id, memo }];
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
        token_id,
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
        token_id,
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
fn register_receive_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    code_hash: String,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let mut store = PrefixedStorage::new(PREFIX_RECEIVERS, &mut deps.storage);
    save(&mut store, sender_raw.as_slice(), &code_hash)?;
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
        may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_else(|| Vec::new());
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
    if minters.len() > 0 {
        save(&mut deps.storage, MINTERS_KEY, &minters)?;
    } else {
        remove(&mut deps.storage, MINTERS_KEY);
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
    //    match msg {
    //      QueryMsg::TokenInfo {} => query_token_info(&deps.storage),
    //    QueryMsg::TokenConfig {} => query_token_config(&deps.storage),
    //  QueryMsg::ExchangeRate {} => query_exchange_rate(&deps.storage),
    //QueryMsg::Minters { .. } => query_minters(deps),
    //        _ => authenticated_queries(deps, msg),
    //  }
    to_binary(&HandleAnswer::SetContractStatus { status: Success })
}

/// Returns StdResult<(Token, u32)>
///
/// returns the token information if the sender has authorization
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * 'block' - a reference to the current BlockInfo
/// * `token_id` - token ID String slice
/// * `tokens` - a reference to the HashMap of token id String to the token storage index
/// * `sender` - a reference to the address trying to get access to the token
/// * `perm_type` - PermissionType we are checking
/// * `oper_for` - a mutable reference to a list of owners that gave the sender "all" permission
/// * `supply_is_public` - true if the token supply is public
fn check_permission<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    block: &BlockInfo,
    token_id: &str,
    tokens: &HashMap<String, u32>,
    sender: &CanonicalAddr,
    perm_type: PermissionType,
    oper_for: &mut Vec<CanonicalAddr>,
    supply_is_public: bool,
) -> StdResult<(Token, u32)> {
    let custom_err = format!(
        "You are not authorized to perform this action on token {}",
        token_id
    );
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(&deps.storage, token_id, tokens, opt_err)?;
    let exp_idx = perm_type.to_u8();
    let owner_slice = token.owner.as_slice();
    // if sender is not the owner and did not already pass with "all" permission for this owner
    if token.owner != *sender && !oper_for.contains(&token.owner) {
        // check if sender has token permission
        if let Some(perm) = token.permissions.iter().find(|&p| p.address == *sender) {
            if let Some(exp) = perm.expirations[exp_idx as usize] {
                if exp.is_expired(block) {
                    return Err(StdError::generic_err(format!(
                        "Access to token {} has expired",
                        token_id
                    )));
                } else {
                    return Ok((token, idx));
                }
            }
        }
        // check if sender has operator permission
        let all_store = ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, &deps.storage);
        let may_list: Option<Vec<Permission>> = json_may_load(&all_store, owner_slice)?;
        if let Some(list) = may_list {
            if let Some(perm) = list.iter().find(|&p| p.address == *sender) {
                if let Some(exp) = perm.expirations[exp_idx as usize] {
                    if exp.is_expired(block) {
                        return Err(StdError::generic_err(format!(
                            "Access to all tokens of {} has expired",
                            &deps.api.human_address(&token.owner)?
                        )));
                    } else {
                        oper_for.push(token.owner.clone());
                        return Ok((token, idx));
                    }
                }
            }
        }
        return Err(StdError::generic_err(custom_err));
    }
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
/// * `tokens` - a reference to the HashMap of token id String to the token storage index
/// * `custom_err` - optional custom error message to use if don't want to reveal that a token
///                  does not exist
fn get_token<S: ReadonlyStorage>(
    storage: &S,
    token_id: &str,
    tokens: &HashMap<String, u32>,
    custom_err: Option<&str>,
) -> StdResult<(Token, u32)> {
    let default_err: String;
    let not_found = if let Some(err) = custom_err {
        err
    } else {
        default_err = format!("Token ID: {} not found", token_id);
        &*default_err
    };
    let idx = tokens
        .get(token_id)
        .ok_or_else(|| StdError::generic_err(not_found))?;
    let info_store = ReadonlyPrefixedStorage::new(PREFIX_INFOS, storage);
    let token: Token = json_may_load(&info_store, &idx.to_le_bytes())?.ok_or_else(|| {
        StdError::generic_err(format!("Unable to find token info for {}", token_id))
    })?;
    Ok((token, *idx))
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
    let tokens: HashMap<String, u32> =
        may_load(storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
    let custom_err = format!("Not authorized to update metadata of token {}", token_id);
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let opt_err = if config.token_supply_is_public {
        None
    } else {
        Some(&*custom_err)
    };
    let (token, idx) = get_token(storage, token_id, &tokens, opt_err)?;
    // do not allow the altering of sealed metadata
    if config.sealed_metadata_is_enabled && prefix == PREFIX_PRIV_META && !token.unwrapped {
        return Err(StdError::generic_err(
            "The private metadata of a sealed token can not be modified",
        ));
    }
    if !(token.owner == *sender && config.owner_may_update_metadata) {
        let minters: Vec<CanonicalAddr> =
            may_load(storage, MINTERS_KEY)?.unwrap_or_else(|| Vec::new());
        if !(minters.contains(sender) && config.minter_may_update_metadata) {
            return Err(StdError::generic_err(custom_err));
        }
    }
    let mut meta_store = PrefixedStorage::new(prefix, storage);
    save(&mut meta_store, &idx.to_le_bytes(), metadata)?;
    Ok(())
}

// enum used to return correct response from SetApproval
pub enum SetAppResp {
    SetApproval,
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
            add: [false, false, false],
            full: [false, false, false],
            remove: [false, false, false],
            clear: [false, false, false],
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
            add: [false, false, false],
            remove: [false, false, false],
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
    pub accesses: [Option<Access>; 3],
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
    let expirations = vec![expiration.clone(), expiration.clone(), expiration];
    let mut alt_all_perm = AlterPermTable::default();
    let mut alt_tok_perm = AlterPermTable::default();
    let mut alt_load_tok_perm = AlterPermTable::default();
    let mut alt_auth_list = AlterAuthTable::default();
    let mut add_load_list = Vec::new();
    let mut load_all = false;
    let mut load_all_exp = vec![
        Expiration::AtHeight(0),
        Expiration::AtHeight(0),
        Expiration::AtHeight(0),
    ];
    let mut all_perm = if proc_info.from_oper {
        all_perm_in.ok_or_else(|| StdError::generic_err("Unable to get operator list"))?
    } else {
        Vec::new()
    };
    let mut oper_pos = 0usize;
    let mut found_perm = false;
    let mut tried_oper = false;

    // do every permission type
    for i in 0..=2usize {
        if let Some(acc) = &proc_info.accesses[i] {
            match acc {
                Access::ApproveToken | Access::RevokeToken => {
                    if !proc_info.token_given {
                        return Err(StdError::generic_err(
                            "Attempted to grant/revoke permission for a token, but did not specify a token ID",
                        ));
                    }
                    let is_approve = if let Access::ApproveToken = acc {
                        true
                    } else {
                        false
                    };
                    // load the "all" permissions if we haven't already and see if the address is there
                    if !tried_oper {
                        if !proc_info.from_oper {
                            let all_store =
                                ReadonlyPrefixedStorage::new(PREFIX_ALL_PERMISSIONS, storage);
                            all_perm = json_may_load(&all_store, owner_slice)?
                                .unwrap_or_else(|| Vec::new());
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
                Access::All | Access::None => {
                    if let Access::All = acc {
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
            all_perm = json_may_load(&all_store, owner_slice)?.unwrap_or_else(|| Vec::new());
        }
        // if there was an update to the "all" permissions
        if alter_perm_list(&mut all_perm, &alt_all_perm, address, &expirations) {
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
            may_load(&auth_store, owner_slice)?.unwrap_or_else(|| Vec::new());
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
                    may_load(&owned_store, owner_slice)?.unwrap_or_else(|| HashSet::new());
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
                    // shouldn't ever fail this check, but let's be safe
                    if load_tok.owner == *owner {
                        if alter_perm_list(
                            &mut load_tok.permissions,
                            &alt_load_tok_perm,
                            address,
                            &load_all_exp,
                        ) {
                            json_save(&mut info_store, &tok_key, &load_tok)?;
                        }
                    }
                }
            }
        }
        let mut updated = false;
        // do for each PermissionType
        for i in 0..=2usize {
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
fn alter_perm_list(
    perms: &mut Vec<Permission>,
    alter_table: &AlterPermTable,
    address: &CanonicalAddr,
    expiration: &[Expiration],
) -> bool {
    let mut updated = false;
    let mut new_perm = Permission {
        address: address.clone(),
        expirations: [None, None, None],
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
    for i in 0..=2usize {
        // if supposed to add permission
        if alter_table.add[i] {
            // if it already has permission for this type
            if let Some(old_exp) = perm.expirations[i] {
                // if the new expiration is different
                if old_exp != expiration[i] {
                    perm.expirations[i] = Some(expiration[i].clone());
                    updated = true;
                }
            // new permission
            } else {
                perm.expirations[i] = Some(expiration[i].clone());
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

// a receiver and their code hash
pub struct ReceiverInfo {
    // the contract address slice
    pub contract: CanonicalAddr,
    // its code hash
    pub code_hash: String,
}

/// Returns a StdResult<Option<CosmosMsg>> used to call a registered contract's ReceiveNft
/// if it has been registered
///
/// # Arguments
///
/// * `storage` - a reference to this contract's storage
/// * `contract_human` - the human address of the contract receiving the token
/// * `contract` - the canonical address of the contract receiving the token
/// * `token_id` - ID String of the token that was sent
/// * `msg` - optional msg used to control ReceiveNft logic
/// * `sender` - the address that is sending the token
/// * `from` - the address of the former owner of the sent token
/// * `receivers` - a mutable reference the list of receiver contracts and their code hashes
fn receiver_callback_msg<S: ReadonlyStorage>(
    storage: &S,
    contract_human: HumanAddr,
    contract: CanonicalAddr,
    token_id: String,
    msg: Option<Binary>,
    sender: HumanAddr,
    from: HumanAddr,
    receivers: &mut Vec<ReceiverInfo>,
) -> StdResult<Option<CosmosMsg>> {
    let code_hash = if let Some(receiver) = receivers.iter().find(|&r| r.contract == contract) {
        receiver.code_hash.clone()
    } else {
        let store = ReadonlyPrefixedStorage::new(PREFIX_RECEIVERS, storage);
        let hash: String = may_load(&store, contract.as_slice())?.unwrap_or_else(|| String::new());
        let receiver = ReceiverInfo {
            contract,
            code_hash: hash.clone(),
        };
        receivers.push(receiver);
        hash
    };
    if code_hash.is_empty() {
        return Ok(None);
    }
    Ok(Some(receive_nft_msg(
        sender,
        from,
        token_id,
        msg,
        code_hash,
        contract_human,
    )?))
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
fn update_owner_inventory<S: Storage>(
    storage: &mut S,
    updates: &[InventoryUpdate],
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
                    for i in 0..=2usize {
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
/// * `tokens` - a reference to the HashMap of token id String to the token storage index
/// * `oper_for` - a mutable reference to a list of owners that gave the sender "all" permission
/// * `inv_updates` - a mutable reference to the list of token inventories to update
/// * `memo` - optional memo for the transfer tx
fn transfer_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    block: &BlockInfo,
    config: &mut Config,
    sender: &CanonicalAddr,
    token_id: String,
    recipient: CanonicalAddr,
    tokens: &HashMap<String, u32>,
    oper_for: &mut Vec<CanonicalAddr>,
    inv_updates: &mut Vec<InventoryUpdate>,
    memo: Option<String>,
) -> StdResult<CanonicalAddr> {
    let (mut token, idx) = check_permission(
        deps,
        block,
        &token_id,
        tokens,
        sender,
        PermissionType::Transfer,
        oper_for,
        config.token_supply_is_public,
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
        let mut new_inv = InventoryUpdate {
            owner: addr,
            retain: HashSet::new(),
            remove: HashSet::new(),
        };
        let (update, found) =
            if let Some(inv) = inv_updates.iter_mut().find(|i| i.owner == new_inv.owner) {
                (inv, true)
            } else {
                let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
                let retain: HashSet<u32> = may_load(&owned_store, new_inv.owner.as_slice())?
                    .unwrap_or_else(|| HashSet::new());
                new_inv.retain = retain;
                (&mut new_inv, false)
            };
        // if updating the recipient's inventory
        if update.owner == recipient {
            update.retain.insert(idx);
        // otherwise updating the old owner's inventory
        } else {
            update.retain.remove(&idx);
            update.remove.insert(idx);
        }
        if !found {
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
    let tokens: HashMap<String, u32> =
        may_load(&deps.storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
    let mut messages: Vec<CosmosMsg> = Vec::new();
    let mut oper_for: Vec<CanonicalAddr> = Vec::new();
    let mut inv_updates: Vec<InventoryUpdate> = Vec::new();
    if let Some(mut xfers) = transfers {
        for xfer in xfers.drain(..) {
            let recipient_raw = deps.api.canonical_address(&xfer.recipient)?;
            let _o = transfer_impl(
                deps,
                &env.block,
                config,
                sender,
                xfer.token_id,
                recipient_raw,
                &tokens,
                &mut oper_for,
                &mut inv_updates,
                xfer.memo,
            )?;
        }
    } else if let Some(mut snds) = sends {
        let mut receivers = Vec::new();
        for send in snds.drain(..) {
            let contract_raw = deps.api.canonical_address(&send.contract)?;
            let owner_raw = transfer_impl(
                deps,
                &env.block,
                config,
                sender,
                send.token_id.clone(),
                contract_raw.clone(),
                &tokens,
                &mut oper_for,
                &mut inv_updates,
                send.memo,
            )?;
            let owner = deps.api.human_address(&owner_raw)?;
            // perform ReceiveNft callback if the receiving contract registered
            let may_callback = receiver_callback_msg(
                &deps.storage,
                send.contract,
                contract_raw,
                send.token_id,
                send.msg,
                env.message.sender.clone(),
                owner,
                &mut receivers,
            )?;
            if let Some(msg) = may_callback {
                messages.push(msg);
            }
        }
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    update_owner_inventory(&mut deps.storage, &inv_updates)?;
    Ok(messages)
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
    let mut tokens: HashMap<String, u32> =
        may_load(&deps.storage, TOKENS_KEY)?.unwrap_or_else(|| HashMap::new());
    let mut oper_for: Vec<CanonicalAddr> = Vec::new();
    let mut inv_updates: Vec<InventoryUpdate> = Vec::new();
    for burn in burns.drain(..) {
        let (token, idx) = check_permission(
            deps,
            block,
            &burn.token_id,
            &tokens,
            sender,
            PermissionType::Transfer,
            &mut oper_for,
            config.token_supply_is_public,
        )?;
        // log the inventory change
        let mut new_inv = InventoryUpdate {
            owner: token.owner.clone(),
            retain: HashSet::new(),
            remove: HashSet::new(),
        };
        let (update, found) =
            if let Some(inv) = inv_updates.iter_mut().find(|i| i.owner == new_inv.owner) {
                (inv, true)
            } else {
                let owned_store = ReadonlyPrefixedStorage::new(PREFIX_OWNED, &deps.storage);
                let retain: HashSet<u32> = may_load(&owned_store, new_inv.owner.as_slice())?
                    .unwrap_or_else(|| HashSet::new());
                new_inv.retain = retain;
                (&mut new_inv, false)
            };
        let token_key = idx.to_le_bytes();
        update.retain.remove(&idx);
        update.remove.insert(idx);
        if !found {
            inv_updates.push(new_inv);
        }
        // remove from token list
        tokens.remove(&burn.token_id);
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
            burn.token_id,
            token.owner,
            brnr,
            burn.memo,
        )?;
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    save(&mut deps.storage, TOKENS_KEY, &tokens)?;
    update_owner_inventory(&mut deps.storage, &inv_updates)?;
    Ok(())
}
