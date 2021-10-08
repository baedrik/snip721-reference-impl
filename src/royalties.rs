use cosmwasm_std::{Api, CanonicalAddr, HumanAddr, StdResult};
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// data for a single royalty
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct Royalty {
    /// address to send royalties to
    pub recipient: HumanAddr,
    /// royalty rate
    pub rate: u16,
}

impl Royalty {
    /// Returns StdResult<StoredRoyalty> from creating a StoredRoyalty from a Royalty
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn to_stored<A: Api>(&self, api: &A) -> StdResult<StoredRoyalty> {
        Ok(StoredRoyalty {
            recipient: api.canonical_address(&self.recipient)?,
            rate: self.rate,
        })
    }
}

/// all royalty information
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct RoyaltyInfo {
    /// decimal places in royalty rates
    pub decimal_places_in_rates: u8,
    /// list of royalties
    pub royalties: Vec<Royalty>,
}

impl RoyaltyInfo {
    /// Returns StdResult<StoredRoyaltyInfo> from creating a StoredRoyaltyInfo from a RoyaltyInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    pub fn to_stored<A: Api>(&self, api: &A) -> StdResult<StoredRoyaltyInfo> {
        Ok(StoredRoyaltyInfo {
            decimal_places_in_rates: self.decimal_places_in_rates,
            royalties: self
                .royalties
                .iter()
                .map(|r| r.to_stored(api))
                .collect::<StdResult<Vec<StoredRoyalty>>>()?,
        })
    }
}

/// display for a single royalty
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct DisplayRoyalty {
    /// address to send royalties to.  Can be None to keep addresses private
    pub recipient: Option<HumanAddr>,
    /// royalty rate
    pub rate: u16,
}

/// display all royalty information
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct DisplayRoyaltyInfo {
    /// decimal places in royalty rates
    pub decimal_places_in_rates: u8,
    /// list of royalties
    pub royalties: Vec<DisplayRoyalty>,
}

/// data for storing a single royalty
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct StoredRoyalty {
    /// address to send royalties to
    pub recipient: CanonicalAddr,
    /// royalty rate
    pub rate: u16,
}

impl StoredRoyalty {
    /// Returns StdResult<DisplayRoyalty> from creating a DisplayRoyalty from a StoredRoyalty
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    /// * `hide_addr` - true if the address should be kept hidden
    pub fn to_human<A: Api>(&self, api: &A, hide_addr: bool) -> StdResult<DisplayRoyalty> {
        let recipient = if hide_addr {
            None
        } else {
            Some(api.human_address(&self.recipient)?)
        };
        Ok(DisplayRoyalty {
            recipient,
            rate: self.rate,
        })
    }
}

/// all stored royalty information
#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
pub struct StoredRoyaltyInfo {
    /// decimal places in royalty rates
    pub decimal_places_in_rates: u8,
    /// list of royalties
    pub royalties: Vec<StoredRoyalty>,
}

impl StoredRoyaltyInfo {
    /// Returns StdResult<DisplayRoyaltyInfo> from creating a DisplayRoyaltyInfo from a StoredRoyaltyInfo
    ///
    /// # Arguments
    ///
    /// * `api` - a reference to the Api used to convert human and canonical addresses
    /// * `hide_addr` - true if the address should be kept hidden
    pub fn to_human<A: Api>(&self, api: &A, hide_addr: bool) -> StdResult<DisplayRoyaltyInfo> {
        Ok(DisplayRoyaltyInfo {
            decimal_places_in_rates: self.decimal_places_in_rates,
            royalties: self
                .royalties
                .iter()
                .map(|r| r.to_human(api, hide_addr))
                .collect::<StdResult<Vec<DisplayRoyalty>>>()?,
        })
    }
}
