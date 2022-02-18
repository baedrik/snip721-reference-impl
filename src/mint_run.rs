use cosmwasm_std::{Api, CanonicalAddr, HumanAddr, StdResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// information about the minting of the NFT
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct MintRunInfo {
    /// optional address of the SNIP-721 contract creator
    pub collection_creator: Option<HumanAddr>,
    /// optional address of this NFT's creator
    pub token_creator: Option<HumanAddr>,
    /// optional time of minting (in seconds since 01/01/1970)
    pub time_of_minting: Option<u64>,
    /// optional number of the mint run this token was minted in.  A mint run represents a
    /// batch of NFTs released at the same time.  So if a creator decided to make 100 copies
    /// of an NFT, they would all be part of mint run number 1.  If they sold quickly, and
    /// the creator wanted to rerelease that NFT, he could make 100 more copies which would all
    /// be part of mint run number 2.
    pub mint_run: Option<u32>,
    /// optional serial number in this mint run.  This is used to serialize
    /// identical NFTs
    pub serial_number: Option<u32>,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}

/// stored information about the minting of the NFT
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct StoredMintRunInfo {
    /// address of this NFT's creator
    pub token_creator: CanonicalAddr,
    /// optional time of minting (in seconds since 01/01/1970)
    pub time_of_minting: u64,
    /// optional number of the mint run this token was minted in.  A mint run represents a
    /// batch of NFTs released at the same time.  So if a creator decided to make 100 copies
    /// of an NFT, they would all be part of mint run number 1.  If they sold quickly, and
    /// the creator wanted to rerelease that NFT, he could make 100 more copies which would all
    /// be part of mint run number 2.
    pub mint_run: Option<u32>,
    /// optional serial number in this mint run.  This is used to serialize
    /// identical NFTs
    pub serial_number: Option<u32>,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}

impl StoredMintRunInfo {
    /// Returns StdResult<MintRunInfo> from creating a MintRunInfo from a StoredMintRunInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    /// * `contract_creator` - the address that instantiated the contract
    pub fn to_human<A: Api>(&self, api: &A, contract_creator: HumanAddr) -> StdResult<MintRunInfo> {
        Ok(MintRunInfo {
            collection_creator: Some(contract_creator),
            token_creator: Some(api.human_address(&self.token_creator)?),
            time_of_minting: Some(self.time_of_minting),
            mint_run: self.mint_run,
            serial_number: self.serial_number,
            quantity_minted_this_run: self.quantity_minted_this_run,
        })
    }
}

/// Serial number to give an NFT when minting
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct SerialNumber {
    /// optional number of the mint run this token will be minted in.  A mint run represents a
    /// batch of NFTs released at the same time.  So if a creator decided to make 100 copies
    /// of an NFT, they would all be part of mint run number 1.  If they sold quickly, and
    /// the creator wanted to rerelease that NFT, he could make 100 more copies which would all
    /// be part of mint run number 2.
    pub mint_run: Option<u32>,
    /// serial number (in this mint run).  This is used to serialize
    /// identical NFTs
    pub serial_number: u32,
    /// optional total number of NFTs minted on this run.  This is used to
    /// represent that this token is number m of n
    pub quantity_minted_this_run: Option<u32>,
}
