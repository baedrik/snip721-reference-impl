use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, Coin, HumanAddr, Uint128};

use crate::expiration::Expiration;
use crate::token::Metadata;

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
    /// optional callback message to execute after instantiation.  This will
    /// most often be used to have the token contract provide its address to a
    /// contract that instantiated it, but it could be used to execute any
    /// contract
    pub post_init_callback: Option<PostInitCallback>,
}

/// This type represents optional configuration values.
/// All values are optional and have defaults which are more private by default,
/// but can be overridden if necessary
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct InitConfig {
    /// indicates whether the token IDs and the number of tokens controlled by the contract are
    /// public.  If the token supply is private, only minters can view the token IDs and
    /// number of tokens controlled by the contract
    /// default: False
    pub public_token_supply: Option<bool>,
    /// indicates whether token ownership is public or private.  A user can still change whether the
    /// ownership of their tokens is public or private
    /// default: False
    pub public_owner: Option<bool>,
    /// indicates whether sealed metadata should be enabled.  If sealed metadata is enabled, the
    /// private metadata is not viewable by anyone, not even the owner, until the owner calls the
    /// Reveal function.  When Reveal is called, the sealed metadata is irreversibly moved to the
    /// public metadata (as default).  if unwrapped_metadata_is_private is set to true, it will
    /// remain as private metadata, but the owner will now be able to see it.  Anyone will be able
    /// to query the token to know that it has been unwrapped.  This simulates buying/selling a
    /// wrapped card that no one knows which card it is until it is unwrapped. If sealed metadata
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

/// info needed to perform a callback message after instantiation
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct PostInitCallback {
    /// the callback message to execute
    pub msg: Binary,
    /// address of the contract to execute
    pub contract_address: HumanAddr,
    /// code hash of the contract to execute
    pub code_hash: String,
    /// list of native Coin to send with the callback message
    pub send: Vec<Coin>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// mint new token
    MintNft {
        /// optional token id. if omitted, use current token index
        token_id: Option<String>,
        /// optional owner address. if omitted, owned by the message sender
        owner: Option<HumanAddr>,
        /// optional public metadata that can be seen by everyone
        public_metadata: Option<Metadata>,
        /// optional private metadata that can only be seen by the owner and whitelist
        private_metadata: Option<Metadata>,
        /// optional memo for the tx
        memo: Option<String>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// Mint multiple tokens
    BatchMintNft {
        /// list of mint operations to perform
        mints: Vec<Mint>,
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
    /// if a contract was instantiated to make ownership public by default, this will allow
    /// an address to make the ownership of their tokens private.  The address can still use
    /// SetGlobalApproval to make ownership public either inventory-wide or for a specific token
    MakeOwnershipPrivate {
        /// optional message length padding
        padding: Option<String>,
    },
    /// add/remove approval(s) that whitelist everyone (makes public)
    SetGlobalApproval {
        /// optional token id to apply approval/revocation to
        token_id: Option<String>,
        /// optional permission level for viewing the owner
        view_owner: Option<AccessLevel>,
        /// optional permission level for viewing private metadata
        view_private_metadata: Option<AccessLevel>,
        /// optional expiration
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// add/remove approval(s) for a specific address on the token(s) you own.  Any permissions
    /// that are omitted will keep the current permission setting for that whitelist address
    SetWhitelistedApproval {
        /// address being granted/revoked permission
        address: HumanAddr,
        /// optional token id to apply approval/revocation to
        token_id: Option<String>,
        /// optional permission level for viewing the owner
        view_owner: Option<AccessLevel>,
        /// optional permission level for viewing private metadata
        view_private_metadata: Option<AccessLevel>,
        /// optional permission level for transferring
        transfer: Option<AccessLevel>,
        /// optional expiration
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// gives the spender permission to transfer the specified token.  If you are the owner
    /// of the token, you can use SetWhitelistedApproval to accomplish the same thing.  If
    /// you are an operator, you can only use Approve
    Approve {
        /// address being granted the permission
        spender: HumanAddr,
        /// id of the token that the spender can transfer
        token_id: String,
        /// optional expiration for this approval
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// revokes the spender's permission to transfer the specified token.  If you are the owner
    /// of the token, you can use SetWhitelistedApproval to accomplish the same thing.  If you
    /// are an operator, you can only use Revoke, but you can not revoke the transfer approval
    /// of another operator
    Revoke {
        /// address whose permission is revoked
        spender: HumanAddr,
        /// id of the token that the spender can no longer transfer
        token_id: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// provided for cw721 compliance, but can be done with SetWhitelistedApproval...
    /// gives the operator permission to transfer all of the message sender's tokens
    ApproveAll {
        /// address being granted permission to transfer
        operator: HumanAddr,
        /// optional expiration for this approval
        expires: Option<Expiration>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// provided for cw721 compliance, but can be done with SetWhitelistedApproval...
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
    /// send a token and call receiving contract's (Batch)ReceiveNft
    SendNft {
        /// address to send the token to
        contract: HumanAddr,
        /// id of the token to send
        token_id: String,
        /// optional message to send with the (Batch)RecieveNft callback
        msg: Option<Binary>,
        /// optional memo for the tx
        memo: Option<String>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// send many tokens and call receiving contracts' (Batch)ReceiveNft
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
    /// register that the message sending contract implements ReceiveNft and possibly
    /// BatchReceiveNft.  If a contract implements BatchReceiveNft, SendNft will always
    /// call BatchReceiveNft even if there is only one token transferred (the token_ids
    /// Vec will only contain one ID)
    RegisterReceiveNft {
        /// receving contract's code hash
        code_hash: String,
        /// optionally true if the contract also implements BatchReceiveNft.  Defaults
        /// to false if not specified
        also_implements_batch_receive_nft: Option<bool>,
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

/// token mint info used when doing a BatchMint
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Mint {
    /// optional token id, if omitted, use current token index
    pub token_id: Option<String>,
    /// optional owner address, owned by the minter otherwise
    pub owner: Option<HumanAddr>,
    /// optional public metadata that can be seen by everyone
    pub public_metadata: Option<Metadata>,
    /// optional private metadata that can only be seen by owner and whitelist
    pub private_metadata: Option<Metadata>,
    /// optional memo for the tx
    pub memo: Option<String>,
}

/// token burn info used when doing a BatchBurnNft
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Burn {
    /// tokens being burnt
    pub token_ids: Vec<String>,
    /// optional memo for the tx
    pub memo: Option<String>,
}

/// token transfer info used when doing a BatchTransferNft
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Transfer {
    /// recipient of the transferred tokens
    pub recipient: HumanAddr,
    /// tokens being transferred
    pub token_ids: Vec<String>,
    /// optional memo for the tx
    pub memo: Option<String>,
}

/// send token info used when doing a BatchSendNft
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Send {
    /// recipient of the sent tokens
    pub contract: HumanAddr,
    /// tokens being sent
    pub token_ids: Vec<String>,
    /// optional message to send with the (Batch)RecieveNft callback
    pub msg: Option<Binary>,
    /// optional memo for the tx
    pub memo: Option<String>,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    /// MintNft will also display the minted token's ID in the log attributes under the
    /// key `minted` in case minting was done as a callback message
    MintNft {
        token_id: String,
    },
    /// BatchMintNft will also display the minted tokens' IDs in the log attributes under the
    /// key `minted` in case minting was done as a callback message
    BatchMintNft {
        token_ids: Vec<String>,
    },
    SetPublicMetadata {
        status: ResponseStatus,
    },
    SetPrivateMetadata {
        status: ResponseStatus,
    },
    MakeOwnershipPrivate {
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
    SetGlobalApproval {
        status: ResponseStatus,
    },
    SetWhitelistedApproval {
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
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
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
    pub memo: Option<String>,
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
    /// display the owner of the specified token if authorized to view it.  If the requester
    /// is also the token's owner, the response will also include a list of any addresses
    /// that can transfer this token.  The transfer approval list is for CW721 compliance,
    /// but the NftDossier query will be more complete by showing viewing approvals as well
    OwnerOf {
        token_id: String,
        /// optional address and key requesting to view the token owner
        viewer: Option<ViewerInfo>,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// displays the public metadata of a token
    NftInfo {
        token_id: String,
    },
    /// displays all the information contained in the OwnerOf and NftInfo queries
    AllNftInfo {
        token_id: String,
        /// optional address and key requesting to view the token owner
        viewer: Option<ViewerInfo>,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// displays the private metadata if permitted to view it
    PrivateMetadata {
        token_id: String,
        /// optional address and key requesting to view the private metadata
        viewer: Option<ViewerInfo>,
    },
    /// displays all the information about a token that the viewer has permission to
    /// see.  This may include the owner, the public metadata, the private metadata, and
    /// the token and inventory approvals
    NftDossier {
        token_id: String,
        /// optional address and key requesting to view the token information
        viewer: Option<ViewerInfo>,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// list all the approvals in place for a specified token if given the owner's viewing
    /// key
    TokenApprovals {
        token_id: String,
        /// the token owner's viewing key
        viewing_key: String,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// list all the inventory-wide approvals in place for the specified address if given the
    /// the correct viewing key for the address
    InventoryApprovals {
        address: HumanAddr,
        /// the viewing key
        viewing_key: String,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// displays a list of all the CW721-style operators (any address that was granted
    /// approval to transfer all of the owner's tokens).  This query is provided to maintain
    /// CW721 compliance, however, approvals are private on secret network, so only the
    /// owner's viewing key will authorize the ability to see the list of operators
    ApprovedForAll {
        owner: HumanAddr,
        /// optional viewing key to authenticate this query.  It is "optional" only in the
        /// sense that a CW721 query does not have this field.  However, not providing the
        /// key will always result in an empty list
        viewing_key: Option<String>,
        /// optionally include expired Approvals in the response list.  If ommitted or
        /// false, expired Approvals will be filtered out of the response
        include_expired: Option<bool>,
    },
    /// displays a list of all the tokens belonging to the input owner in which the viewer
    /// has view_owner permission
    Tokens {
        owner: HumanAddr,
        /// optional address of the querier if different from the owner
        viewer: Option<HumanAddr>,
        /// optional viewing key
        viewing_key: Option<String>,
        /// optionally display only token ids that come after the input String in
        /// lexicographical order
        start_after: Option<String>,
        /// optional number of token ids to display
        limit: Option<u32>,
    },
    /// display if a token is unwrapped
    IsUnwrapped {
        token_id: String,
    },
    /// verify that the specified address has approval to transfer every listed token
    VerifyTransferApproval {
        /// list of tokens to verify approval for
        token_ids: Vec<String>,
        /// address that has approval
        address: HumanAddr,
        /// viewing key
        viewing_key: String,
    },
    /// display the transaction history for the specified address in reverse
    /// chronological order
    TransactionHistory {
        address: HumanAddr,
        /// viewing key
        viewing_key: String,
        /// optional page to display
        page: Option<u32>,
        /// optional number of transactions per page
        page_size: Option<u32>,
    },
    /// display the code hash a contract has registered with the token contract and whether
    /// the contract implements BatchReceivenft
    RegisteredCodeHash {
        /// the contract whose receive registration info you want to view
        contract: HumanAddr,
    },

    // Keplr compatibility
    TokenInfo {},
    Balance {
        address: HumanAddr,
        key: String,
    },
}

/// SNIP721 Approval
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct Snip721Approval {
    /// whitelisted address
    pub address: HumanAddr,
    /// optional expiration if the address has view owner permission
    pub view_owner_expiration: Option<Expiration>,
    /// optional expiration if the address has view private metadata permission
    pub view_private_metadata_expiration: Option<Expiration>,
    /// optional expiration if the address has transfer permission
    pub transfer_expiration: Option<Expiration>,
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
    /// Owner of the token if permitted to view it
    pub owner: Option<HumanAddr>,
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
    TokenApprovals {
        owner_is_public: bool,
        public_ownership_expiration: Option<Expiration>,
        private_metadata_is_public: bool,
        private_metadata_is_public_expiration: Option<Expiration>,
        token_approvals: Vec<Snip721Approval>,
    },
    InventoryApprovals {
        owner_is_public: bool,
        public_ownership_expiration: Option<Expiration>,
        private_metadata_is_public: bool,
        private_metadata_is_public_expiration: Option<Expiration>,
        inventory_approvals: Vec<Snip721Approval>,
    },
    NftInfo {
        name: Option<String>,
        description: Option<String>,
        image: Option<String>,
    },
    PrivateMetadata {
        name: Option<String>,
        description: Option<String>,
        image: Option<String>,
    },
    AllNftInfo {
        access: Cw721OwnerOfResponse,
        info: Option<Metadata>,
    },
    NftDossier {
        owner: Option<HumanAddr>,
        public_metadata: Option<Metadata>,
        private_metadata: Option<Metadata>,
        display_private_metadata_error: Option<String>,
        owner_is_public: bool,
        public_ownership_expiration: Option<Expiration>,
        private_metadata_is_public: bool,
        private_metadata_is_public_expiration: Option<Expiration>,
        token_approvals: Option<Vec<Snip721Approval>>,
        inventory_approvals: Option<Vec<Snip721Approval>>,
    },
    ApprovedForAll {
        operators: Vec<Cw721Approval>,
    },
    IsUnwrapped {
        token_is_unwrapped: bool,
    },
    VerifyTransferApproval {
        approved_for_all: bool,
        first_unapproved_token: Option<String>,
    },
    TransactionHistory {
        txs: Vec<Tx>,
    },
    RegisteredCodeHash {
        code_hash: Option<String>,
        also_implements_batch_receive_nft: bool,
    },

    // Keplr compatibility
    TokenInfo {
        name: String,
        symbol: String,
        decimals: u8,
        total_supply: Option<Uint128>,
    },
    Balance {
        amount: Uint128,
    },
}

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
