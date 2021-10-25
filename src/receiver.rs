use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, CosmosMsg, HumanAddr, StdResult};

use secret_toolkit::utils::HandleCallback;

use crate::contract::BLOCK_SIZE;

/// used to create ReceiveNft and BatchReceiveNft callback messages.  BatchReceiveNft is preferred
/// over ReceiveNft, because ReceiveNft does not allow the recipient to know who sent the token,
/// only its previous owner, and ReceiveNft can only process one token.  So it is inefficient when
/// sending multiple tokens to the same contract (a deck of game cards for instance).  ReceiveNft
/// primarily exists just to maintain CW-721 compliance.  Also, it should be noted that the CW-721
/// `sender` field is inaccurately named, because it is used to hold the address the token came from,
/// not the address that sent it (which is not always the same).  The name is reluctantly kept in
/// ReceiveNft to maintain CW-721 compliance, but BatchReceiveNft uses `sender` to hold the sending
/// address (which matches both its true role and its SNIP-20 Receive counterpart).  Any contract
/// that is implementing both Receiver Interfaces must be sure that the ReceiveNft `sender` field
/// is actually processed like a BatchReceiveNft `from` field.  Again, apologies for any confusion
/// caused by propagating inaccuracies, but because InterNFT is planning on using CW-721 standards,
/// compliance with CW-721 might be necessary
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Snip721ReceiveMsg {
    /// ReceiveNft may be a HandleMsg variant of any contract that wants to implement a receiver
    /// interface.  BatchReceiveNft, which is more informative and more efficient, is preferred over
    /// ReceiveNft.  Please read above regarding why ReceiveNft, which follows CW-721 standard has an
    /// inaccurately named `sender` field
    ReceiveNft {
        /// previous owner of sent token
        sender: HumanAddr,
        /// token that was sent
        token_id: String,
        /// optional message to control receiving logic
        msg: Option<Binary>,
    },
    /// BatchReceiveNft may be a HandleMsg variant of any contract that wants to implement a receiver
    /// interface.  BatchReceiveNft, which is more informative and more efficient, is preferred over
    /// ReceiveNft.
    BatchReceiveNft {
        /// address that sent the tokens.  There is no ReceiveNft field equivalent to this
        sender: HumanAddr,
        /// previous owner of sent tokens.  This is equivalent to the ReceiveNft `sender` field
        from: HumanAddr,
        /// tokens that were sent
        token_ids: Vec<String>,
        /// optional message to control receiving logic
        msg: Option<Binary>,
    },
}

impl HandleCallback for Snip721ReceiveMsg {
    const BLOCK_SIZE: usize = BLOCK_SIZE;
}

/// Returns a StdResult<CosmosMsg> used to call a registered contract's ReceiveNft
///
/// # Arguments
///
/// * `sender` - the address of the former owner of the sent token
/// * `token_id` - ID String of the token that was sent
/// * `msg` - optional msg used to control ReceiveNft logic
/// * `callback_code_hash` - String holding the code hash of the contract that was
///                          sent the token
/// * `contract_addr` - address of the contract that was sent the token
pub fn receive_nft_msg(
    sender: HumanAddr,
    token_id: String,
    msg: Option<Binary>,
    callback_code_hash: String,
    contract_addr: HumanAddr,
) -> StdResult<CosmosMsg> {
    let msg = Snip721ReceiveMsg::ReceiveNft {
        sender,
        token_id,
        msg,
    };
    msg.to_cosmos_msg(callback_code_hash, contract_addr, None)
}

/// Returns a StdResult<CosmosMsg> used to call a registered contract's
/// BatchReceiveNft
///
/// # Arguments
///
/// * `sender` - the address that is sending the token
/// * `from` - the address of the former owner of the sent token
/// * `token_ids` - list of ID Strings of the tokens that were sent
/// * `msg` - optional msg used to control ReceiveNft logic
/// * `callback_code_hash` - String holding the code hash of the contract that was
///                          sent the token
/// * `contract_addr` - address of the contract that was sent the token
pub fn batch_receive_nft_msg(
    sender: HumanAddr,
    from: HumanAddr,
    token_ids: Vec<String>,
    msg: Option<Binary>,
    callback_code_hash: String,
    contract_addr: HumanAddr,
) -> StdResult<CosmosMsg> {
    let msg = Snip721ReceiveMsg::BatchReceiveNft {
        sender,
        from,
        token_ids,
        msg,
    };
    msg.to_cosmos_msg(callback_code_hash, contract_addr, None)
}
