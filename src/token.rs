use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::CanonicalAddr;

use crate::state::Permission;

/// token
#[derive(Serialize, Deserialize)]
pub struct Token {
    /// owner
    pub owner: CanonicalAddr,
    /// permissions granted for this token
    pub permissions: Vec<Permission>,
    /// true if this token has been unwrapped.  If sealed metadata is not enabled, all
    /// tokens are considered unwrapped
    pub unwrapped: bool,
}

/// token metadata
#[derive(Serialize, Deserialize, JsonSchema, Clone, PartialEq, Debug)]
pub struct Metadata {
    /// optional indentifier
    pub name: Option<String>,
    /// optional description
    pub description: Option<String>,
    /// optional uri to contain an image, additional data fields, etc...
    pub image: Option<String>,
}
