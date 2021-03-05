use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, CosmosMsg, HumanAddr, StdResult};

use secret_toolkit::utils::HandleCallback;

use crate::contract::BLOCK_SIZE;

/// used to create a ReceiveNft callback message
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum Snip721ReceiveNftMsg {
    /// ReceiveNft should be a HandleMsg variant of any contract that wants to implement
    /// SendNft/ReceiveNft functionality
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
}

impl HandleCallback for Snip721ReceiveNftMsg {
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
    let msg = Snip721ReceiveNftMsg::ReceiveNft {
        sender,
        from,
        token_id,
        msg,
    };
    Ok(msg.to_cosmos_msg(callback_code_hash, contract_addr, None)?)
}
