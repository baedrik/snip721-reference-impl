use std::any::type_name;

use cosmwasm_std::{Api, CanonicalAddr, HumanAddr, ReadonlyStorage, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};

use secret_toolkit::{
    serialization::{Bincode2, Json, Serde},
    storage::{AppendStore, AppendStoreMut},
};

use schemars::JsonSchema;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::expiration::Expiration;

/// storage key for config
pub const CONFIG_KEY: &[u8] = b"config";
/// storage key for the BlockInfo when the last handle was executed
pub const BLOCK_KEY: &[u8] = b"blockinfo";
/// storage key for minters
pub const MINTERS_KEY: &[u8] = b"minters";
/// storage key for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// storage key for token id map
pub const IDS_KEY: &[u8] = b"ids";
/// storage key for token index map
pub const INDEX_KEY: &[u8] = b"indices";
/// prefix for storage of token infos
pub const PREFIX_INFOS: &[u8] = b"infos";
/// prefix for the storage of public metadata
pub const PREFIX_PUB_META: &[u8] = b"publicmeta";
/// prefix for the storage of private metadata
pub const PREFIX_PRIV_META: &[u8] = b"privatemeta";
/// prefix for storage of txs
pub const PREFIX_TXS: &[u8] = b"rawtxs";
/// prefix for storage of tx ids
pub const PREFIX_TX_IDS: &[u8] = b"txids";
/// prefix for storage of an owner's list of tokens
pub const PREFIX_OWNED: &[u8] = b"owned";
/// prefix for storage of owner's list of "all" permissions
pub const PREFIX_ALL_PERMISSIONS: &[u8] = b"allpermissions";
/// prefix for storage of owner's list of tokens permitted to addresses
pub const PREFIX_AUTHLIST: &[u8] = b"authlist";
/// prefix for storage of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkeys";
/// prefix for the storage of the code hashes of contract's that have implemented ReceiveNft
pub const PREFIX_RECEIVERS: &[u8] = b"receivers";

/// Token contract config
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct Config {
    /// name of token contract
    pub name: String,
    /// token contract symbol
    pub symbol: String,
    /// admin address
    pub admin: CanonicalAddr,
    /// count of mint ops
    pub mint_cnt: u32,
    /// count of tx
    pub tx_cnt: u64,
    /// contract status
    pub status: u8,
    /// are token IDs/count public
    pub token_supply_is_public: bool,
    /// is ownership public
    pub owner_is_public: bool,
    /// is private metadata enabled
    pub private_metadata_is_enabled: bool,
    /// is sealed metadata enabled
    pub sealed_metadata_is_enabled: bool,
    /// should Reveal unwrap to private metadata
    pub unwrap_to_private: bool,
    /// is a minter permitted to update a token's metadata
    pub minter_may_update_metadata: bool,
    /// is the token's owner permitted to update the token's metadata
    pub owner_may_update_metadata: bool,
    /// is burn enabled
    pub burn_is_enabled: bool,
}

/// tx type and specifics
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub enum TxAction {
    /// transferred token ownership
    Transfer {
        /// previous owner
        from: HumanAddr,
        /// optional sender if not owner
        #[serde(skip_serializing_if = "Option::is_none")]
        sender: Option<HumanAddr>,
        /// new owner
        recipient: HumanAddr,
    },
    /// minted new token
    Mint {
        /// minter's address
        minter: HumanAddr,
        /// token's first owner
        recipient: HumanAddr,
    },
    /// burned a token
    Burn {
        /// previous owner
        owner: HumanAddr,
        /// burner's address if not owner
        #[serde(skip_serializing_if = "Option::is_none")]
        burner: Option<HumanAddr>,
    },
}

/// tx for display
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
#[serde(rename_all = "snake_case")]
pub struct Tx {
    /// tx id
    pub tx_id: u64,
    /// the block containing this tx
    pub blockheight: u64,
    /// token id
    pub token_id: String,
    /// tx type and specifics
    pub action: TxAction,
    /// optional memo
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memo: Option<String>,
}

impl Tx {
    /// Returns StdResult<StoredTx> from converting a displayable tx to a stored tx
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn into_stored<A: Api>(self, api: &A) -> StdResult<StoredTx> {
        let action = match self.action {
            TxAction::Transfer {
                from,
                sender,
                recipient,
            } => {
                let sndr = if let Some(s) = sender {
                    Some(api.canonical_address(&s)?)
                } else {
                    None
                };
                StoredTxAction::Transfer {
                    from: api.canonical_address(&from)?,
                    sender: sndr,
                    recipient: api.canonical_address(&recipient)?,
                }
            }
            TxAction::Mint { minter, recipient } => StoredTxAction::Mint {
                minter: api.canonical_address(&minter)?,
                recipient: api.canonical_address(&recipient)?,
            },
            TxAction::Burn { owner, burner } => {
                let bnr = if let Some(b) = burner {
                    Some(api.canonical_address(&b)?)
                } else {
                    None
                };
                StoredTxAction::Burn {
                    owner: api.canonical_address(&owner)?,
                    burner: bnr,
                }
            }
        };
        let tx = StoredTx {
            tx_id: self.tx_id,
            blockheight: self.blockheight,
            token_id: self.token_id,
            action,
            memo: self.memo,
        };
        Ok(tx)
    }
}

/// tx type and specifics
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub enum StoredTxAction {
    /// transferred token ownership
    Transfer {
        /// previous owner
        from: CanonicalAddr,
        /// optional sender if not owner
        sender: Option<CanonicalAddr>,
        /// new owner
        recipient: CanonicalAddr,
    },
    /// minted new token
    Mint {
        /// minter's address
        minter: CanonicalAddr,
        /// token's first owner
        recipient: CanonicalAddr,
    },
    /// burned a token
    Burn {
        /// previous owner
        owner: CanonicalAddr,
        /// burner's address if not owner
        burner: Option<CanonicalAddr>,
    },
}

/// tx in storage
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct StoredTx {
    /// tx id
    pub tx_id: u64,
    /// the block containing this tx
    pub blockheight: u64,
    /// token id
    pub token_id: String,
    /// tx type and specifics
    pub action: StoredTxAction,
    /// optional memo
    pub memo: Option<String>,
}

impl StoredTx {
    /// Returns StdResult<Tx> from converting a stored tx to a displayable tx
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn into_humanized<A: Api>(self, api: &A) -> StdResult<Tx> {
        let action = match self.action {
            StoredTxAction::Transfer {
                from,
                sender,
                recipient,
            } => {
                let sndr = if let Some(s) = sender {
                    Some(api.human_address(&s)?)
                } else {
                    None
                };
                TxAction::Transfer {
                    from: api.human_address(&from)?,
                    sender: sndr,
                    recipient: api.human_address(&recipient)?,
                }
            }
            StoredTxAction::Mint { minter, recipient } => TxAction::Mint {
                minter: api.human_address(&minter)?,
                recipient: api.human_address(&recipient)?,
            },
            StoredTxAction::Burn { owner, burner } => {
                let bnr = if let Some(b) = burner {
                    Some(api.human_address(&b)?)
                } else {
                    None
                };
                TxAction::Burn {
                    owner: api.human_address(&owner)?,
                    burner: bnr,
                }
            }
        };
        let tx = Tx {
            tx_id: self.tx_id,
            blockheight: self.blockheight,
            token_id: self.token_id,
            action,
            memo: self.memo,
        };

        Ok(tx)
    }
}

/// Returns StdResult<()> after storing tx
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `config` - a mutable reference to the contract Config
/// * `blockheight` - the block containing this tx
/// * `token_id` - token id being minted
/// * `from` - the previouis owner's address
/// * `sender` - optional address that sent the token
/// * `recipient` - the recipient's address
/// * `memo` - optional memo for the tx
pub fn store_transfer<S: Storage>(
    storage: &mut S,
    config: &mut Config,
    blockheight: u64,
    token_id: String,
    from: CanonicalAddr,
    sender: Option<CanonicalAddr>,
    recipient: CanonicalAddr,
    memo: Option<String>,
) -> StdResult<()> {
    let action = StoredTxAction::Transfer {
        from,
        sender,
        recipient,
    };
    let tx = StoredTx {
        tx_id: config.tx_cnt,
        blockheight,
        token_id,
        action,
        memo,
    };
    append_tx(storage, &tx)?;
    if let StoredTxAction::Transfer {
        from,
        sender,
        recipient,
    } = tx.action
    {
        append_tx_for_addr(storage, config.tx_cnt, &from)?;
        append_tx_for_addr(storage, config.tx_cnt, &recipient)?;
        if let Some(sndr) = sender.as_ref() {
            if *sndr != recipient {
                append_tx_for_addr(storage, config.tx_cnt, sndr)?;
            }
        }
    }
    config.tx_cnt += 1;
    Ok(())
}

/// Returns StdResult<()> after storing tx
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `config` - a mutable reference to the contract Config
/// * `blockheight` - the block containing this tx
/// * `token_id` - token id being minted
/// * `minter` - the minter's address
/// * `recipient` - the recipient's address
/// * `memo` - optional memo for the tx
pub fn store_mint<S: Storage>(
    storage: &mut S,
    config: &mut Config,
    blockheight: u64,
    token_id: String,
    minter: CanonicalAddr,
    recipient: CanonicalAddr,
    memo: Option<String>,
) -> StdResult<()> {
    let action = StoredTxAction::Mint { minter, recipient };
    let tx = StoredTx {
        tx_id: config.tx_cnt,
        blockheight,
        token_id,
        action,
        memo,
    };
    append_tx(storage, &tx)?;
    if let StoredTxAction::Mint { minter, recipient } = tx.action {
        append_tx_for_addr(storage, config.tx_cnt, &recipient)?;
        if recipient != minter {
            append_tx_for_addr(storage, config.tx_cnt, &minter)?;
        }
    }
    config.tx_cnt += 1;
    Ok(())
}

/// Returns StdResult<()> after storing tx
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `config` - a mutable reference to the contract Config
/// * `blockheight` - the block containing this tx
/// * `token_id` - token id being minted
/// * `owner` - the previous owner's address
/// * `burner` - optional address that burnt the token
/// * `memo` - optional memo for the tx
pub fn store_burn<S: Storage>(
    storage: &mut S,
    config: &mut Config,
    blockheight: u64,
    token_id: String,
    owner: CanonicalAddr,
    burner: Option<CanonicalAddr>,
    memo: Option<String>,
) -> StdResult<()> {
    let action = StoredTxAction::Burn { owner, burner };
    let tx = StoredTx {
        tx_id: config.tx_cnt,
        blockheight,
        token_id,
        action,
        memo,
    };
    append_tx(storage, &tx)?;
    if let StoredTxAction::Burn { owner, burner } = tx.action {
        append_tx_for_addr(storage, config.tx_cnt, &owner)?;
        if let Some(bnr) = burner.as_ref() {
            append_tx_for_addr(storage, config.tx_cnt, bnr)?;
        }
    }
    config.tx_cnt += 1;
    Ok(())
}

/// Returns StdResult<()> after saving tx
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `tx` - a reference to the tx to store
fn append_tx<S: Storage>(storage: &mut S, tx: &StoredTx) -> StdResult<()> {
    let mut store = PrefixedStorage::new(PREFIX_TXS, storage);
    let mut store = AppendStoreMut::attach_or_create_with_serialization(&mut store, Json)?;
    store.push(tx)
}

/// Returns StdResult<()> after saving tx id
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `tx_id` - the tx id to store
/// * `address` - a reference to the address for which to store this tx id
fn append_tx_for_addr<S: Storage>(
    storage: &mut S,
    tx_id: u64,
    address: &CanonicalAddr,
) -> StdResult<()> {
    let mut store = PrefixedStorage::multilevel(&[PREFIX_TX_IDS, address.as_slice()], storage);
    let mut store = AppendStoreMut::attach_or_create(&mut store)?;
    store.push(&tx_id)
}

/// Returns StdResult<Vec<Tx>> of the txs to display
///
/// # Arguments
///
/// * `api` - a reference to the Api used to convert human and canonical addresses
/// * `storage` - a reference to the contract's storage
/// * `address` - a reference to the address whose txs to display
/// * `page` - page to start displaying
/// * `page_size` - number of txs per page
pub fn get_txs<A: Api, S: ReadonlyStorage>(
    api: &A,
    storage: &S,
    address: &CanonicalAddr,
    page: u32,
    page_size: u32,
) -> StdResult<Vec<Tx>> {
    let id_store =
        ReadonlyPrefixedStorage::multilevel(&[PREFIX_TX_IDS, address.as_slice()], storage);

    // Try to access the storage of tx ids for the account.
    // If it doesn't exist yet, return an empty list of txs.
    let id_store = if let Some(result) = AppendStore::<u32, _>::attach(&id_store) {
        result?
    } else {
        return Ok(vec![]);
    };
    // try to access tx storage
    let tx_store = ReadonlyPrefixedStorage::new(PREFIX_TXS, storage);
    //    let tx_store = if let Some(res) =
    //      AppendStore::<StoredTx, _, _>::attach_with_serialization(&tx_store, Json) {
    //        res?
    //  } else {
    //    return Err(StdError::generic_err(
    //      "Unable to retrieve tx data",
    //            ));
    //      };
    let tx_store = AppendStore::<StoredTx, _, _>::attach_with_serialization(&tx_store, Json)
        .ok_or_else(|| StdError::generic_err("Unable to retrieve tx data"))??;
    // Take `page_size` txs starting from the latest tx, potentially skipping `page * page_size`
    // txs from the start.
    let txs: StdResult<Vec<Tx>> = id_store
        .iter()
        .rev()
        .skip((page * page_size) as usize)
        .take(page_size as usize)
        .map(|id| {
            id.map(|id| tx_store.get_at(id).and_then(|tx| tx.into_humanized(api)))
                .and_then(|x| x)
        })
        .collect();

    txs
}

/// permission to view token info/transfer tokens
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Permission {
    /// permitted address
    pub address: CanonicalAddr,
    /// list of permission expirations for this address
    pub expirations: [Option<Expiration>; 3],
}

/// permission types
#[derive(Serialize, Deserialize, Debug)]
pub enum PermissionType {
    ViewOwner,
    ViewMetadata,
    Transfer,
}

impl PermissionType {
    /// Returns usize representation of the enum variant
    pub fn to_u8(&self) -> u8 {
        match self {
            PermissionType::ViewOwner => 0,
            PermissionType::ViewMetadata => 1,
            PermissionType::Transfer => 2,
        }
    }
}

// probably delete this
/// metadata types
#[derive(Serialize, Deserialize)]
pub enum MetadataType {
    Public,
    Private,
}

impl MetadataType {
    /// Returns usize representation of the enum variant
    pub fn to_u8(&self) -> u8 {
        match self {
            MetadataType::Public => 0,
            MetadataType::Private => 1,
        }
    }
}

/// list of one owner's tokens authorized to a single address
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthList {
    /// whitelisted address
    pub address: CanonicalAddr,
    /// lists of tokens address has access to
    pub tokens: [Vec<u32>; 3],
}

/// Returns StdResult<()> resulting from saving an item to storage
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `key` - a byte slice representing the key to access the stored item
/// * `value` - a reference to the item to store
pub fn save<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}

/// Removes an item from storage
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn remove<S: Storage>(storage: &mut S, key: &[u8]) {
    storage.remove(key);
}

/// Returns StdResult<T> from retrieving the item with the specified key.  Returns a
/// StdError::NotFound if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn load<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Bincode2::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

/// Returns StdResult<Option<T>> from retrieving the item with the specified key.
/// Returns Ok(None) if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Bincode2::deserialize(&value).map(Some),
        None => Ok(None),
    }
}

/// Returns StdResult<()> resulting from saving an item to storage using Json (de)serialization
/// because bincode2 annoyingly uses a float op when deserializing an enum
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `key` - a byte slice representing the key to access the stored item
/// * `value` - a reference to the item to store
pub fn json_save<T: Serialize, S: Storage>(
    storage: &mut S,
    key: &[u8],
    value: &T,
) -> StdResult<()> {
    storage.set(key, &Json::serialize(value)?);
    Ok(())
}

/// Returns StdResult<T> from retrieving the item with the specified key using Json
/// (de)serialization because bincode2 annoyingly uses a float op when deserializing an enum.  
/// Returns a StdError::NotFound if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn json_load<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Json::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

/// Returns StdResult<Option<T>> from retrieving the item with the specified key using Json
/// (de)serialization because bincode2 annoyingly uses a float op when deserializing an enum.
/// Returns Ok(None) if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn json_may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Json::deserialize(&value).map(Some),
        None => Ok(None),
    }
}
