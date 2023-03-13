#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use cosmwasm_std::testing::*;
    use cosmwasm_std::{Api, StdError};

    use crate::inventory::{Inventory, InventoryIter};

    #[test]
    fn test_inventory() {
        let mut deps = mock_dependencies();
        let alice = "alice".to_string();
        let alice_raw = deps.api.addr_canonicalize(&alice).unwrap();
        let mut inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();

        // test trying to remove a token when the list is empty
        inventory.remove(&mut deps.storage, 100, false).unwrap();
        assert_eq!(inventory.cnt, 0);
        // test to_set with empty inventory
        let set = inventory.to_set(&deps.storage).unwrap();
        assert!(set.is_empty());
        // test iterator with empty inventory
        let mut iter = InventoryIter::new(&inventory);
        assert!(iter.next(&deps.storage).unwrap().is_none());

        // add a token to the inventory
        inventory.insert(&mut deps.storage, 100, false).unwrap();
        assert_eq!(inventory.cnt, 1);

        // test adding token already in the inventory
        inventory.insert(&mut deps.storage, 100, false).unwrap();
        assert_eq!(inventory.cnt, 1);

        // add 3 more tokens
        inventory.insert(&mut deps.storage, 200, false).unwrap();
        inventory.insert(&mut deps.storage, 300, false).unwrap();
        inventory.insert(&mut deps.storage, 400, false).unwrap();
        assert_eq!(inventory.cnt, 4);

        let expected = [100u32, 200, 300, 400];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);
        // test contains
        assert!(inventory.contains(&deps.storage, 300).unwrap());
        assert!(!inventory.contains(&deps.storage, 350).unwrap());
        // test owns
        assert!(Inventory::owns(&deps.storage, &alice_raw, 200).unwrap());
        assert!(!Inventory::owns(&deps.storage, &alice_raw, 250).unwrap());

        // remove 2 tokens from the inventory
        inventory.remove(&mut deps.storage, 100, false).unwrap();
        inventory.remove(&mut deps.storage, 300, false).unwrap();
        // remove one already removed
        inventory.remove(&mut deps.storage, 300, false).unwrap();

        // test saving the inventory
        inventory.save(&mut deps.storage).unwrap();
        // reload it
        let mut inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();

        assert_eq!(inventory.cnt, 2);

        let expected = [400u32, 200];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // insert another
        inventory.insert(&mut deps.storage, 500, true).unwrap();
        assert_eq!(inventory.cnt, 3);

        let expected = [400u32, 200, 500];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // insert another
        inventory.insert(&mut deps.storage, 600, true).unwrap();
        assert_eq!(inventory.cnt, 4);

        let expected = [400u32, 200, 500, 600];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // insert another
        inventory.insert(&mut deps.storage, 700, true).unwrap();
        // try duplicate
        inventory.insert(&mut deps.storage, 700, true).unwrap();
        assert_eq!(inventory.cnt, 5);

        let expected = [400u32, 200, 500, 600, 700];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // remove one
        inventory.remove(&mut deps.storage, 600, true).unwrap();
        // try duplicate
        inventory.remove(&mut deps.storage, 600, true).unwrap();

        assert_eq!(inventory.cnt, 4);

        let expected = [400u32, 200, 500, 700];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // test contains
        assert!(inventory.contains(&deps.storage, 500).unwrap());
        assert!(!inventory.contains(&deps.storage, 600).unwrap());
        // test owns
        assert!(Inventory::owns(&deps.storage, &alice_raw, 500).unwrap());
        assert!(!Inventory::owns(&deps.storage, &alice_raw, 600).unwrap());

        // remove the rest
        inventory.remove(&mut deps.storage, 700, true).unwrap();
        inventory.remove(&mut deps.storage, 500, true).unwrap();
        inventory.remove(&mut deps.storage, 200, true).unwrap();
        inventory.remove(&mut deps.storage, 400, true).unwrap();

        let mut inventory = Inventory::new(&deps.storage, alice_raw).unwrap();

        assert_eq!(inventory.cnt, 0);
        // test to_set with empty inventory
        let set = inventory.to_set(&deps.storage).unwrap();
        assert!(set.is_empty());
        // test iterator with empty inventory
        let mut iter = InventoryIter::new(&inventory);
        assert!(iter.next(&deps.storage).unwrap().is_none());

        inventory.insert(&mut deps.storage, 800, false).unwrap();
        inventory.insert(&mut deps.storage, 900, false).unwrap();
        inventory.insert(&mut deps.storage, 1000, true).unwrap();
        inventory.insert(&mut deps.storage, 1100, false).unwrap();
        inventory.insert(&mut deps.storage, 1200, false).unwrap();
        inventory.insert(&mut deps.storage, 1300, true).unwrap();

        assert_eq!(inventory.cnt, 6);

        let expected = [800u32, 900, 1000, 1100, 1200, 1300];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(expected);
        // verify to_set
        let set = inventory.to_set(&deps.storage).unwrap();
        assert_eq!(set, expected_set);
        // verify InventoryIter
        let mut iter = InventoryIter::new(&inventory);
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // test start after the first element
        let expected = [900u32, 1000, 1100, 1200, 1300];
        // verify InventoryIter
        let mut iter =
            InventoryIter::start_after(&deps.storage, &inventory, 800, "No Error").unwrap();
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // test start after a middle element
        let expected = [1100u32, 1200, 1300];
        // verify InventoryIter
        let mut iter =
            InventoryIter::start_after(&deps.storage, &inventory, 1000, "No Error").unwrap();
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // test start after the last element
        let expected: Vec<u32> = Vec::new();
        // verify InventoryIter
        let mut iter =
            InventoryIter::start_after(&deps.storage, &inventory, 1300, "No Error").unwrap();
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // test start after non-existing element
        // verify InventoryIter
        let res = InventoryIter::start_after(&deps.storage, &inventory, 345, "Expect Error");
        assert_eq!(
            res.err(),
            Some(StdError::generic_err("Expect Error".to_string()))
        );
    }
}
