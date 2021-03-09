use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, HumanAddr, Uint128};

use crate::expiration::Expiration;
use crate::state::Tx;
use crate::token::Metadata;
use crate::viewing_key::ViewingKey;

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// name of token contract
    pub name: String,
    /// token contract symbol
    pub symbol: String,
    /// optional admin address, env.message.sender if missing
    pub admin: Option<HumanAddr>,
    /// entropy used for prng seed
    pub entropy: String,
    /// optional privacy configuration for the contract
    pub config: Option<InitConfig>,
}

/// This type represents optional configuration values which can be overridden.
/// All values are optional and have defaults which are more private by default,
/// but can be overridden if necessary
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
#[serde(rename_all = "snake_case")]
pub struct InitConfig {
    /// indicates whether the token IDs and the number of tokens controlled by the contract are
    /// public.  If the token supply is private, only minters can view the token IDs and
    /// number of tokens controlled by the contract
    /// default: False
    pub public_token_supply: Option<bool>,
    /// indicates whether token ownership is public or private when a token is minted.  The
    /// owner can change the ownership privacy level later, but if the current owner transfers
    /// the token, ownership privacy will return to this setting.
    /// default: False
    pub public_owner: Option<bool>,
    /// indicates whether sealed metadata should be enabled.  If sealed metadata is enabled, the
    /// private metadata is not viewable by anyone, not even the owner, until the owner calls the
    /// Reveal function.  When Reveal is called, the sealed metadata is irreversibly moved to the
    /// public metadata (as default).  if unwrapped_metadata_is_private is set to true, it will
    /// remain as private metadata, but the owner will now be able to see it.  Anyone will be able
    /// to query the token to know that it has been unwrapped.  This simulates buying/selling a
    /// wrapped card that non one knows which card it is until it is unwrapped. If sealed metadata
    /// is not enabled, all tokens are considered unwrapped
    /// default:  False
    pub enable_sealed_metadata: Option<bool>,
    /// indicates if the Reveal function should keep the sealed metadata private after unwrapping
    /// This config value is ignored if sealed metadata is not enabled
    /// default: False
    pub unwrapped_metadata_is_private: Option<bool>,
    /// indicates whether a minter is permitted to update a token's metadata
    /// default: True
    pub minter_may_update_metadata: Option<bool>,
    /// indicates whether the owner of a token is permitted to update a token's metadata
    /// default: False
    pub owner_may_update_metadata: Option<bool>,
    /// Indicates whether burn functionality should be enabled
    /// default: False
    pub enable_burn: Option<bool>,
}

impl Default for InitConfig {
    fn default() -> Self {
        InitConfig {
            public_token_supply: Some(false),
            public_owner: Some(false),
            enable_sealed_metadata: Some(false),
            unwrapped_metadata_is_private: Some(false),
            minter_may_update_metadata: Some(true),
            owner_may_update_metadata: Some(false),
            enable_burn: Some(false),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// mint new token
    Mint {
        /// optional token id, if omitted, use current token index
        token_id: Option<String>,
        /// optional owner address, owned by the minter otherwise
        owner: Option<HumanAddr>,
        /// optional public metadata that can be seen by everyone
        public_metadata: Option<Metadata>,
        /// optional private metadata that can only be seen by owner and whitelist
        private_metadata: Option<Metadata>,
        /// optional memo for the tx
        memo: Option<String>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set the public metadata.  This can be called by either the token owner or a valid minter
    /// if they have been given this power by the appropriate config values
    SetPublicMetadata {
        /// id of the token whose public metadata should be updated
        token_id: String,
        /// the new public metadata
        metadata: Metadata,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set the private metadata.  This can be called by either the token owner or a valid minter
    /// if they have been given this power by the appropriate config values
    SetPrivateMetadata {
        /// id of the token whose private metadata should be updated
        token_id: String,
        /// the new private metadata
        metadata: Metadata,
        /// optional message length padding
        padding: Option<String>,
    },
    /// Reveal the private metadata of a sealed token and mark the token as having been unwrapped
    Reveal {
        /// id of the token to unwrap
        token_id: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set approval(s) for token(s) you own.  Any permissions that are omitted will keep current permission
    SetApproval {
        /// address being granted permission
        address: HumanAddr,
        /// optional token id to apply approval to
        token_id: Option<String>,
        /// optional permission to view owner
        view_owner: Option<AccessLevel>,
        /// optional permission to view private metadata
        view_private_metadata: Option<AccessLevel>,
        /// optional permission to transfer
        transfer: Option<AccessLevel>,
        /// optional expiration
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// gives the spender permission to transfer the specified token.  If you are the owner of the token, you
    /// can use SetApproval to accomplish the same thing.  If you are an operator, you can only use Approve
    Approve {
        /// address being granted the permission
        spender: HumanAddr,
        /// id of the token that spender can transfer
        token_id: String,
        /// optional expiration for this approval
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// revokes the spender's permission to transfer the specified token.  If you are the owner of the token, you
    /// can use SetApproval to accomplish the same thing.  If you are an operator, you can only use Revoke, but
    /// you can not revoke the transfer permission of another operator
    Revoke {
        /// address whose permission is revoked
        spender: HumanAddr,
        /// id of the token that spender can no longer transfer
        token_id: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// provided for cw721 compliance, but can be done with SetApproval...
    /// gives the operator permission to transfer all of the message sender's tokens
    ApproveAll {
        /// address being granted permission to transfer
        operator: HumanAddr,
        /// optional expiration for this approval
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// provided for cw721 compliance, but can be done with SetApproval...
    /// revokes the operator's permission to transfer any of the message sender's tokens
    RevokeAll {
        /// address whose permissions are revoked
        operator: HumanAddr,
        /// optional message length padding
        padding: Option<String>,
    },
    /// transfer a token
    TransferNft {
        /// recipient of the transfer
        recipient: HumanAddr,
        /// id of the token to transfer
        token_id: String,
        /// optional memo for the tx
        memo: Option<String>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// transfer many tokens
    BatchTransferNft {
        /// list of transfers to perform
        transfers: Vec<Transfer>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// send a token and call receiving contract's ReceiveNft
    SendNft {
        /// contract to send the token to
        contract: HumanAddr,
        /// id of the token to send
        token_id: String,
        /// optional message to send with the RecieveNft callback
        msg: Option<Binary>,
        /// optional memo for the tx
        memo: Option<String>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// send many tokens and call receiving contracts' ReceiveNft
    BatchSendNft {
        /// list of sends to perform
        sends: Vec<Send>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// burn a token
    BurnNft {
        /// token to burn
        token_id: String,
        /// optional memo for the tx
        memo: Option<String>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// burn many tokens
    BatchBurnNft {
        /// list of burns to perform
        burns: Vec<Burn>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// register that the contract implements ReceiveNft
    RegisterReceiveNft {
        /// receving contract's code hash
        code_hash: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// create a viewing key
    CreateViewingKey {
        /// entropy String used in random key generation
        entropy: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set viewing key
    SetViewingKey {
        /// desired viewing key
        key: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// add addresses with minting authority
    AddMinters {
        /// list of addresses that can now mint
        minters: Vec<HumanAddr>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// revoke minting authority from addresses
    RemoveMinters {
        /// list of addresses no longer allowed to mint
        minters: Vec<HumanAddr>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// define list of addresses with minting authority
    SetMinters {
        /// list of addresses with minting authority
        minters: Vec<HumanAddr>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// change address with administrative power
    ChangeAdmin {
        /// address with admin authority
        address: HumanAddr,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set contract status level to determine which functions are allowed.  StopTransactions
    /// status prevent mints, burns, sends, and transfers, but allows all other functions
    SetContractStatus {
        /// status level
        level: ContractStatus,
        /// optional message length padding
        padding: Option<String>,
    },
}

/// permission access level
#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum AccessLevel {
    /// approve permission only for the specified token
    ApproveToken,
    /// grant permission for all tokens
    All,
    /// revoke permission only for the specified token
    RevokeToken,
    /// remove all permissions for this address
    None,
}

/// token burn info used when doing a BatchBurnNft
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Burn {
    /// token being burnt
    pub token_id: String,
    /// optional memo for the tx
    pub memo: Option<String>,
}

/// token transfer info used when doing a BatchTransferNft
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Transfer {
    /// recipient of the transferred token
    pub recipient: HumanAddr,
    /// token being transferred
    pub token_id: String,
    /// optional memo for the tx
    pub memo: Option<String>,
}

/// send token info used when doing a BatchSendNft
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct Send {
    /// recipient of the sent token
    pub contract: HumanAddr,
    /// token being sent
    pub token_id: String,
    /// optional message to send with the RecieveNft callback
    pub msg: Option<Binary>,
    /// optional memo for the tx
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    Mint {
        status: ResponseStatus,
    },
    SetPublicMetadata {
        status: ResponseStatus,
    },
    SetPrivateMetadata {
        status: ResponseStatus,
    },
    Reveal {
        status: ResponseStatus,
    },
    Approve {
        status: ResponseStatus,
    },
    Revoke {
        status: ResponseStatus,
    },
    ApproveAll {
        status: ResponseStatus,
    },
    RevokeAll {
        status: ResponseStatus,
    },
    SetApproval {
        status: ResponseStatus,
    },
    TransferNft {
        status: ResponseStatus,
    },
    BatchTransferNft {
        status: ResponseStatus,
    },
    SendNft {
        status: ResponseStatus,
    },
    BatchSendNft {
        status: ResponseStatus,
    },
    BurnNft {
        status: ResponseStatus,
    },
    BatchBurnNft {
        status: ResponseStatus,
    },
    RegisterReceiveNft {
        status: ResponseStatus,
    },
    /// response from both setting and creating a viewing key
    ViewingKey {
        key: String,
    },
    AddMinters {
        status: ResponseStatus,
    },
    RemoveMinters {
        status: ResponseStatus,
    },
    SetMinters {
        status: ResponseStatus,
    },
    ChangeAdmin {
        status: ResponseStatus,
    },
    SetContractStatus {
        status: ResponseStatus,
    },
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ViewerInfo {
    // querying address
    pub address: HumanAddr,
    // authentication key string
    pub viewing_key: String,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the contract's name and symbol
    ContractInfo {},
    /// display the contract's configuration
    ContractConfig {},
    /// display the list of authorized minters
    Minters {},
    /// display the number of tokens controlled by the contract.  The token supply must
    /// either be public, or the querier must be an authenticated minter
    NumTokens {
        /// optional address and key requesting to view the number of tokens
        viewer: Option<ViewerInfo>,
    },
    /// display an optionally paginated list of all the tokens controlled by the contract.
    /// The token supply must either be public, or the querier must be an authenticated
    /// minter
    AllTokens {
        /// optional address and key requesting to view the list of tokens
        viewer: Option<ViewerInfo>,
        /// optionally display only token ids that come after the input String in
        /// lexicographical order
        start_after: Option<String>,
        /// optional number of token ids to display
        limit: Option<u32>,
    },
    /// display the owner of the specified token if authorized to view it
    OwnerOf {
        token_id: String,
        /// optional address and key requesting to view the token owner
        viewer: Option<ViewerInfo>,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// display if a token has been unwrapped
    WasTokenUnwrapped { token_id: String },
    /*
        Allowance {
            owner: HumanAddr,
            spender: HumanAddr,
            key: String,
        },
        Balance {
            address: HumanAddr,
            key: String,
        },
        TransferHistory {
            address: HumanAddr,
            key: String,
            page: Option<u32>,
            page_size: u32,
        },
        TransactionHistory {
            address: HumanAddr,
            key: String,
            page: Option<u32>,
            page_size: u32,
        },
    */
}

/// CW721 Approval
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Cw721Approval {
    /// address that can transfer the token
    pub spender: HumanAddr,
    /// expiration of this approval
    pub expires: Expiration,
}

/// response of CW721 OwnerOf
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Cw721OwnerOfResponse {
    /// Owner of the token
    pub owner: HumanAddr,
    /// list of addresses approved to transfer this token
    pub approvals: Vec<Cw721Approval>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    ContractInfo {
        name: String,
        symbol: String,
    },
    ContractConfig {
        token_supply_is_public: bool,
        owner_is_public: bool,
        sealed_metadata_is_enabled: bool,
        unwrapped_metadata_is_private: bool,
        minter_may_update_metadata: bool,
        owner_may_update_metadata: bool,
        burn_is_enabled: bool,
    },
    Minters {
        minters: Vec<HumanAddr>,
    },
    NumTokens {
        count: u32,
    },
    TokenList {
        tokens: Vec<String>,
    },
    OwnerOf {
        owner: HumanAddr,
        approvals: Vec<Cw721Approval>,
    },
    WasTokenUnwrapped {
        token_was_unwrapped: bool,
    },
}

///

/*
impl QueryMsg {
    pub fn get_validation_params(&self) -> (Vec<&HumanAddr>, ViewingKey) {
        match self {
            Self::Balance { address, key } => (vec![address], ViewingKey(key.clone())),
            Self::TransferHistory { address, key, .. } => (vec![address], ViewingKey(key.clone())),
            Self::TransactionHistory { address, key, .. } => {
                (vec![address], ViewingKey(key.clone()))
            }
            Self::Allowance {
                owner,
                spender,
                key,
                ..
            } => (vec![owner, spender], ViewingKey(key.clone())),
            _ => panic!("This query type does not require authentication"),
        }
    }
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    TokenInfo {
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: Option<Uint128>,
    },
    ExchangeRate {
        rate: Uint128,
        denom: String,
    },
    Allowance {
        spender: HumanAddr,
        owner: HumanAddr,
        allowance: Uint128,
        expiration: Option<u64>,
    },
    Balance {
        amount: Uint128,
    },
    TransactionHistory {
        txs: Vec<Tx>,
    },
    ViewingKeyError {
        msg: String,
    },

}


#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema)]
pub struct CreateViewingKeyResponse {
    pub key: String,
}
*/

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Normal,
    StopTransactions,
    StopAll,
}

impl ContractStatus {
    /// Returns u8 representation of the ContractStatus
    pub fn to_u8(&self) -> u8 {
        match self {
            ContractStatus::Normal => 0,
            ContractStatus::StopTransactions => 1,
            ContractStatus::StopAll => 2,
        }
    }
}
