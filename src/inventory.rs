use std::collections::HashSet;

use cosmwasm_std::{CanonicalAddr, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use serde::{Deserialize, Serialize};

use crate::state::{may_load, remove, save};

/// storage prefix for an owner's inventory count
pub const PREFIX_INVENTORY_COUNT: &[u8] = b"invcnt";
/// storage prefix for mapping a token idx to an inventory index
pub const PREFIX_INVENTORY_MAP: &[u8] = b"invmap";
/// storage prefix for a token idx in the inventory
pub const PREFIX_INVENTORY_TOKEN: &[u8] = b"invtok";

/// token inventory
#[derive(Serialize, Deserialize)]
pub struct Inventory {
    /// owner's address
    pub owner: CanonicalAddr,
    /// number of tokens in the inventory
    pub cnt: u32,
}

impl Inventory {
    /// Returns StdResult<Inventory>
    ///
    /// creates a new Inventory by loading it from storage or creating a new one
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `owner` - the owner's address
    pub fn new(storage: &dyn Storage, owner: CanonicalAddr) -> StdResult<Self> {
        let store = ReadonlyPrefixedStorage::new(storage, PREFIX_INVENTORY_COUNT);

        Ok(Inventory {
            cnt: may_load::<u32>(&store, owner.as_slice())?.unwrap_or(0),
            owner,
        })
    }

    /// Returns StdResult<()>
    ///
    /// adds a token to the inventory
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    /// * `token_idx` - the token's idx
    /// * `save_cnt` - true if the inventory count should be saved
    pub fn insert(
        &mut self,
        storage: &mut dyn Storage,
        token_idx: u32,
        save_cnt: bool,
    ) -> StdResult<()> {
        let owner_slice = self.owner.as_slice();
        let mut map_store =
            PrefixedStorage::multilevel(storage, &[PREFIX_INVENTORY_MAP, owner_slice]);
        let token_key = token_idx.to_le_bytes();
        // nothing to do if the token idx is already in the inventory
        if may_load::<u32>(&map_store, &token_key)?.is_some() {
            return Ok(());
        }
        // map the new token to the top index
        save(&mut map_store, &token_key, &self.cnt)?;
        // save the token idx
        let mut token_store =
            PrefixedStorage::multilevel(storage, &[PREFIX_INVENTORY_TOKEN, owner_slice]);
        save(&mut token_store, &self.cnt.to_le_bytes(), &token_idx)?;
        // increment the count
        self.cnt = self.cnt.checked_add(1).ok_or_else(|| {
            StdError::generic_err(
                "This would put your token count above the amount supported by the contract",
            )
        })?;
        // save the count if desired
        if save_cnt {
            let mut cnt_store = PrefixedStorage::new(storage, PREFIX_INVENTORY_COUNT);
            save(&mut cnt_store, owner_slice, &self.cnt)?;
        }
        Ok(())
    }

    /// Returns StdResult<()>
    ///
    /// removes a token from the inventory
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    /// * `token_idx` - the token's idx
    /// * `save_cnt` - true if the inventory count should be saved
    pub fn remove(
        &mut self,
        storage: &mut dyn Storage,
        token_idx: u32,
        save_cnt: bool,
    ) -> StdResult<()> {
        let owner_slice = self.owner.as_slice();
        let mut map_store =
            PrefixedStorage::multilevel(storage, &[PREFIX_INVENTORY_MAP, owner_slice]);
        let token_key = token_idx.to_le_bytes();
        // if the token is in the inventory
        if let Some(inv_idx) = may_load::<u32>(&map_store, &token_key)? {
            // remove it from the map
            remove(&mut map_store, &token_key);
            // decrement the count
            self.cnt = self.cnt.saturating_sub(1);
            // if it was not the last element
            if inv_idx != self.cnt {
                // get the last token
                let mut token_store =
                    PrefixedStorage::multilevel(storage, &[PREFIX_INVENTORY_TOKEN, owner_slice]);
                let last_tkn: u32 = may_load(&token_store, &self.cnt.to_le_bytes())?
                    .ok_or_else(|| StdError::generic_err("Inventory token storage is corrupt"))?;
                // swap the last token to the position of the removed token
                save(&mut token_store, &inv_idx.to_le_bytes(), &last_tkn)?;
                // change the previous last token's mapping
                let mut map_store =
                    PrefixedStorage::multilevel(storage, &[PREFIX_INVENTORY_MAP, owner_slice]);
                save(&mut map_store, &last_tkn.to_le_bytes(), &inv_idx)?;
            }

            // save the count if desired
            if save_cnt {
                let mut cnt_store = PrefixedStorage::new(storage, PREFIX_INVENTORY_COUNT);
                save(&mut cnt_store, owner_slice, &self.cnt)?;
            }
        }
        Ok(())
    }

    /// Returns StdResult<HashSet<u32>>
    ///
    /// creates a HashSet from the Inventory
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    pub fn to_set(&self, storage: &dyn Storage) -> StdResult<HashSet<u32>> {
        let mut set: HashSet<u32> = HashSet::new();
        let token_store = ReadonlyPrefixedStorage::multilevel(
            storage,
            &[PREFIX_INVENTORY_TOKEN, self.owner.as_slice()],
        );
        for idx in 0..self.cnt {
            let token_idx: u32 = may_load(&token_store, &idx.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Inventory token storage is corrupt"))?;
            set.insert(token_idx);
        }
        Ok(set)
    }

    /// Returns StdResult<bool>
    ///
    /// returns true if the inventory contains the input token_idx
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `token_idx` - the token index in question
    pub fn contains(&self, storage: &dyn Storage, token_idx: u32) -> StdResult<bool> {
        let map_store = ReadonlyPrefixedStorage::multilevel(
            storage,
            &[PREFIX_INVENTORY_MAP, self.owner.as_slice()],
        );
        Ok(may_load::<u32>(&map_store, &token_idx.to_le_bytes())?.is_some())
    }

    /// Returns StdResult<bool>
    ///
    /// returns true if the input address owns the input token_idx
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `owner` - a reference to the presumed owner's address
    /// * `token_idx` - the token index in question
    pub fn owns(storage: &dyn Storage, owner: &CanonicalAddr, token_idx: u32) -> StdResult<bool> {
        let map_store =
            ReadonlyPrefixedStorage::multilevel(storage, &[PREFIX_INVENTORY_MAP, owner.as_slice()]);
        Ok(may_load::<u32>(&map_store, &token_idx.to_le_bytes())?.is_some())
    }

    /// Returns StdResult<()>
    ///
    /// saves the inventory count
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    pub fn save(&self, storage: &mut dyn Storage) -> StdResult<()> {
        let mut cnt_store = PrefixedStorage::new(storage, PREFIX_INVENTORY_COUNT);
        save(&mut cnt_store, self.owner.as_slice(), &self.cnt)
    }
}

/// an "iterator" (deos not implement the trait) over an Inventory
pub struct InventoryIter<'a> {
    /// a reference to the Inventory to iterate
    pub inventory: &'a Inventory,
    /// the current index to retrieve
    pub curr: u32,
}

impl<'a> InventoryIter<'a> {
    /// Returns InventoryIter
    ///
    /// creates a new InventoryIter
    ///
    /// # Arguments
    ///
    /// * `inventory` - a reference to the Inventory to iterate over
    pub fn new(inventory: &'a Inventory) -> Self {
        InventoryIter { inventory, curr: 0 }
    }

    /// Returns StdResult<InventoryIter>
    ///
    /// creates an InventoryIter that starts after the supplied token index
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    /// * `inventory` - a reference to the Inventory to iterate over
    /// * `token_idx` - optional token_index to start iterating after
    /// * `err_msg` - error message if the token index is not in the inventory
    pub fn start_after(
        storage: &dyn Storage,
        inventory: &'a Inventory,
        token_idx: u32,
        err_msg: &str,
    ) -> StdResult<Self> {
        let map_store = ReadonlyPrefixedStorage::multilevel(
            storage,
            &[PREFIX_INVENTORY_MAP, inventory.owner.as_slice()],
        );
        let mut curr = may_load::<u32>(&map_store, &token_idx.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err(err_msg))?;
        curr = curr.saturating_add(1);
        Ok(InventoryIter { inventory, curr })
    }

    /// Returns StdResult<Option<u32>>
    ///
    /// returns the next token_idx in the inventory
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    pub fn next(&mut self, storage: &dyn Storage) -> StdResult<Option<u32>> {
        // at the end
        if self.curr >= self.inventory.cnt {
            return Ok(None);
        }
        let token_store = ReadonlyPrefixedStorage::multilevel(
            storage,
            &[PREFIX_INVENTORY_TOKEN, self.inventory.owner.as_slice()],
        );
        let this = self.curr;
        // bump the position
        self.curr = self.curr.saturating_add(1);
        may_load::<u32>(&token_store, &this.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err("Inventory token storage is corrupt"))
            .map(Some)
    }
}
