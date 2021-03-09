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
    /// the owner has the ability to globally make ownership or private metadata public
    /// so the global permission is contained here.  This would make it trivial to also
    /// allow an owner to grant global transfer permission, but this implementation will
    /// not provide a function to change that setting
    pub global_permissions: [bool; 3],
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
