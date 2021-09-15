use crate::state::{may_load, remove, save};
use cosmwasm_std::{CanonicalAddr, ReadonlyStorage, StdError, StdResult, Storage};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// storage prefix for an owner's inventory information
pub const PREFIX_INVENTORY_INFO: &[u8] = b"invinfo";
/// storage prefix for mapping a token idx to an inventory index
pub const PREFIX_INVENTORY_MAP: &[u8] = b"invmap";
/// storage prefix for inventory cells
pub const PREFIX_INVENTORY_CELL: &[u8] = b"invcell";

/// list element
#[derive(Serialize, Deserialize)]
pub struct Cell {
    /// true if the cell is free
    is_free: bool,
    /// if the cell is free, the index of the next free cell or None
    /// if the cell is occupied, the token index
    index: Option<u32>,
}

/// inventory info
#[derive(Serialize, Deserialize)]
pub struct InventoryInfo {
    /// next available index number
    pub top: u32,
    /// number of tokens in the list
    pub count: u32,
    /// index of the first free cell
    pub free: Option<u32>,
}

/// token inventory
#[derive(Serialize, Deserialize)]
pub struct Inventory {
    /// owner's address
    pub owner: CanonicalAddr,
    /// info for this inventory
    pub info: InventoryInfo,
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
    pub fn new<S: ReadonlyStorage>(storage: &S, owner: CanonicalAddr) -> StdResult<Self> {
        let store = ReadonlyPrefixedStorage::new(PREFIX_INVENTORY_INFO, storage);
        let info: InventoryInfo = may_load(&store, owner.as_slice())?.unwrap_or(InventoryInfo {
            top: 0,
            count: 0,
            free: None,
        });
        Ok(Inventory { owner, info })
    }

    /// Returns StdResult<()>
    ///
    /// adds a token to the inventory
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    /// * `token_idx` - the token's idx
    /// * `save_info` - true if the inventory info should be saved
    pub fn insert<S: Storage>(
        &mut self,
        storage: &mut S,
        token_idx: u32,
        save_info: bool,
    ) -> StdResult<()> {
        let owner_slice = self.owner.as_slice();
        let map_store =
            ReadonlyPrefixedStorage::multilevel(&[PREFIX_INVENTORY_MAP, owner_slice], storage);
        let token_key = token_idx.to_le_bytes();
        // nothing to do if the token idx is already in the inventory
        if may_load::<u32, _>(&map_store, &token_key)?.is_some() {
            return Ok(());
        }
        let mut cell_store =
            PrefixedStorage::multilevel(&[PREFIX_INVENTORY_CELL, owner_slice], storage);
        let inv_idx = if let Some(fr) = self.info.free {
            // grab the free cell
            let cell: Cell = may_load(&cell_store, &fr.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Inventory free cell storage is corrupt"))?;
            if !cell.is_free {
                return Err(StdError::generic_err(
                    "Cell should be free but it is occupied",
                ));
            }
            self.info.free = cell.index;
            fr
        } else {
            // add to top
            let idx = self.info.top;
            self.info.top = self.info.top.checked_add(1).ok_or_else(|| {
                StdError::generic_err(
                    "This would put your token count above the amount supported by the contract",
                )
            })?;
            idx
        };
        let new_cell = Cell {
            is_free: false,
            index: Some(token_idx),
        };
        // save inventory element
        save(&mut cell_store, &inv_idx.to_le_bytes(), &new_cell)?;
        // save to the map
        let mut map_store =
            PrefixedStorage::multilevel(&[PREFIX_INVENTORY_MAP, owner_slice], storage);
        save(&mut map_store, &token_key, &inv_idx)?;
        // increment the count
        self.info.count = self.info.count.checked_add(1).ok_or_else(|| {
            StdError::generic_err(
                "This would put your token count above the amount supported by the contract",
            )
        })?;
        // save the InventoryInfo if desired
        if save_info {
            let mut info_store = PrefixedStorage::new(PREFIX_INVENTORY_INFO, storage);
            save(&mut info_store, owner_slice, &self.info)?;
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
    /// * `save_info` - true if the inventory info should be saved
    pub fn remove<S: Storage>(
        &mut self,
        storage: &mut S,
        token_idx: u32,
        save_info: bool,
    ) -> StdResult<()> {
        let owner_slice = self.owner.as_slice();
        let mut map_store =
            PrefixedStorage::multilevel(&[PREFIX_INVENTORY_MAP, owner_slice], storage);
        let token_key = token_idx.to_le_bytes();
        // if the token is in the inventory
        if let Some(inv_idx) = may_load::<u32, _>(&map_store, &token_key)? {
            // remove it from the map
            remove(&mut map_store, &token_key);
            let free_cell = Cell {
                is_free: true,
                index: self.info.free,
            };
            // push the newly freed cell onto the free stack
            self.info.free = Some(inv_idx);
            // decrement the count
            self.info.count = self.info.count.saturating_sub(1);
            // save the freed cell
            let mut cell_store =
                PrefixedStorage::multilevel(&[PREFIX_INVENTORY_CELL, owner_slice], storage);
            save(&mut cell_store, &inv_idx.to_le_bytes(), &free_cell)?;
            // save the InventoryInfo if desired
            if save_info {
                let mut info_store = PrefixedStorage::new(PREFIX_INVENTORY_INFO, storage);
                save(&mut info_store, owner_slice, &self.info)?;
            }
        }
        Ok(())
    }

    /// Returns StdResult<HashSet<u32>>
    ///
    /// creates a HashSet from the Inventory, optionally omitting a specified token_idx
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    pub fn to_set<S: ReadonlyStorage>(&self, storage: &S) -> StdResult<HashSet<u32>> {
        let mut set: HashSet<u32> = HashSet::new();
        let cell_store = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_INVENTORY_CELL, self.owner.as_slice()],
            storage,
        );
        for idx in 0..self.info.top {
            let cell: Cell = may_load(&cell_store, &idx.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Inventory cell storage is corrupt"))?;
            if !cell.is_free {
                set.insert(cell.index.ok_or_else(|| {
                    StdError::generic_err("Inventory occupied cell index is corrupt")
                })?);
            }
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
    pub fn contains<S: ReadonlyStorage>(&self, storage: &S, token_idx: u32) -> StdResult<bool> {
        let map_store = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_INVENTORY_MAP, self.owner.as_slice()],
            storage,
        );
        Ok(may_load::<u32, _>(&map_store, &token_idx.to_le_bytes())?.is_some())
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
    pub fn owns<S: ReadonlyStorage>(
        storage: &S,
        owner: &CanonicalAddr,
        token_idx: u32,
    ) -> StdResult<bool> {
        let map_store =
            ReadonlyPrefixedStorage::multilevel(&[PREFIX_INVENTORY_MAP, owner.as_slice()], storage);
        Ok(may_load::<u32, _>(&map_store, &token_idx.to_le_bytes())?.is_some())
    }

    /// Returns StdResult<()>
    ///
    /// saves the inventory info
    ///
    /// # Arguments
    ///
    /// * `storage` - a mutable reference to the contract's storage
    pub fn save<S: Storage>(&self, storage: &mut S) -> StdResult<()> {
        let mut info_store = PrefixedStorage::new(PREFIX_INVENTORY_INFO, storage);
        save(&mut info_store, self.owner.as_slice(), &self.info)
    }
}

/// an "iterator" (deos not implement the trait) over an Inventory
pub struct InventoryIter<'a> {
    /// a reference to the Inventory to iterate
    pub inventory: &'a Inventory,
    /// the current index to retrieve
    pub curr: u32,
    /// the count of indexes already retrieved
    pub retrieve_cnt: u32,
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
        InventoryIter {
            inventory,
            curr: 0,
            retrieve_cnt: 0,
        }
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
    pub fn start_after<S: ReadonlyStorage>(
        storage: &S,
        inventory: &'a Inventory,
        token_idx: u32,
        err_msg: &str,
    ) -> StdResult<Self> {
        let map_store = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_INVENTORY_MAP, inventory.owner.as_slice()],
            storage,
        );
        let mut curr = may_load::<u32, _>(&map_store, &token_idx.to_le_bytes())?
            .ok_or_else(|| StdError::generic_err(err_msg))?;
        curr = curr.saturating_add(1);
        Ok(InventoryIter {
            inventory,
            curr,
            retrieve_cnt: 0,
        })
    }

    /// Returns StdResult<Option<u32>>
    ///
    /// returns the next token_idx in the inventory
    ///
    /// # Arguments
    ///
    /// * `storage` - a reference to the contract's storage
    pub fn next<S: ReadonlyStorage>(&mut self, storage: &S) -> StdResult<Option<u32>> {
        let cell_store = ReadonlyPrefixedStorage::multilevel(
            &[PREFIX_INVENTORY_CELL, self.inventory.owner.as_slice()],
            storage,
        );
        // get the next occupied cell
        while self.curr < self.inventory.info.top && self.retrieve_cnt < self.inventory.info.count {
            let cell: Cell = may_load(&cell_store, &self.curr.to_le_bytes())?
                .ok_or_else(|| StdError::generic_err("Inventory cell storage is corrupt"))?;
            // don't need checked_add, because it can't be at u32::MAX if it is < top
            self.curr += 1;
            // if an occupied cell
            if !cell.is_free {
                let idx = cell.index.ok_or_else(|| {
                    StdError::generic_err("Occupied Inventory cell index is corrupt")
                })?;
                self.retrieve_cnt += 1;
                return Ok(Some(idx));
            }
        }
        Ok(None)
    }
}
