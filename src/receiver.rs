use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, CosmosMsg, HumanAddr, StdResult};

use secret_toolkit::utils::HandleCallback;

use crate::contract::BLOCK_SIZE;

/// used to create ReceiveNft and BatchReceiveNft callback messages
/// BatchReceiveNft is obviously more flexible and can do the equivalent of
/// ReceiveNft if there is only one token_id in the list, but ReceiveNft
/// exists just to maintain cw721 compliance, since cw721 does not do any
/// batch transfer optimization
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Snip721ReceiveMsg {
    /// ReceiveNft should be a HandleMsg variant of any contract that wants to implement
    /// SendNft/ReceiveNft functionality. BatchReceiveNft is obviously more flexible and
    /// can do the equivalent of ReceiveNft if there is only one token_id in the list,
    /// but ReceiveNft exists just to maintain cw721 compliance, since cw721 does not do any
    /// batch transfer optimization
    ReceiveNft {
        /// address that sent the token
        sender: HumanAddr,
        /// previous owner of sent token
        from: HumanAddr,
        /// token that was sent
        token_id: String,
        /// optional message to control receiving logic
        msg: Option<Binary>,
    },
    /// BatchReceiveNft should be a HandleMsg variant of any contract that wants to implement
    /// BatchSendNft/BatchReceiveNft functionality
    BatchReceiveNft {
        /// address that sent the tokens
        sender: HumanAddr,
        /// previous owner of sent tokens
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
/// * `sender` - the address that is sending the token
/// * `from` - the address of the former owner of the sent token
/// * `token_id` - ID String of the token that was sent
/// * `msg` - optional msg used to control ReceiveNft logic
/// * `callback_code_hash` - String holding the code hash of the contract that was
///                          sent the token
/// * `contract_addr` - address of the contract that was sent the token
pub fn receive_nft_msg(
    sender: HumanAddr,
    from: HumanAddr,
    token_id: String,
    msg: Option<Binary>,
    callback_code_hash: String,
    contract_addr: HumanAddr,
) -> StdResult<CosmosMsg> {
    let msg = Snip721ReceiveMsg::ReceiveNft {
        sender,
        from,
        token_id,
        msg,
    };
    Ok(msg.to_cosmos_msg(callback_code_hash, contract_addr, None)?)
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
    Ok(msg.to_cosmos_msg(callback_code_hash, contract_addr, None)?)
}
