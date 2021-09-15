#[cfg(test)]
mod tests {
    use crate::inventory::{Inventory, InventoryIter};
    use cosmwasm_std::testing::*;
    use cosmwasm_std::{Api, HumanAddr, StdError};
    use std::collections::HashSet;

    #[test]
    fn test_inventory() {
        let mut deps = mock_dependencies(20, &[]);
        let alice = HumanAddr("alice".to_string());
        let alice_raw = deps.api.canonical_address(&alice).unwrap();
        let mut inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();

        // test trying to remove a token when the list is empty
        inventory.remove(&mut deps.storage, 100, false).unwrap();
        assert_eq!(inventory.info.count, 0);
        // test to_set with empty inventory
        let set = inventory.to_set(&deps.storage).unwrap();
        assert!(set.is_empty());
        // test iterator with empty inventory
        let mut iter = InventoryIter::new(&inventory);
        assert!(iter.next(&deps.storage).unwrap().is_none());

        // add a token to the inventory
        inventory.insert(&mut deps.storage, 100, false).unwrap();
        assert_eq!(inventory.info.count, 1);
        assert_eq!(inventory.info.top, 1);

        // test adding token already in the inventory
        inventory.insert(&mut deps.storage, 100, false).unwrap();
        assert_eq!(inventory.info.count, 1);
        assert_eq!(inventory.info.top, 1);

        // add 3 more tokens
        inventory.insert(&mut deps.storage, 200, false).unwrap();
        inventory.insert(&mut deps.storage, 300, false).unwrap();
        inventory.insert(&mut deps.storage, 400, false).unwrap();
        assert_eq!(inventory.info.count, 4);
        assert_eq!(inventory.info.top, 4);
        assert_eq!(inventory.info.free, None);

        let expected = [100u32, 200, 300, 400];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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

        assert_eq!(inventory.info.count, 2);
        assert_eq!(inventory.info.top, 4);
        assert_eq!(inventory.info.free, Some(2));

        let expected = [200u32, 400];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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

        // insert that will use a free cell
        inventory.insert(&mut deps.storage, 500, true).unwrap();
        assert_eq!(inventory.info.count, 3);
        assert_eq!(inventory.info.top, 4);
        assert_eq!(inventory.info.free, Some(0));

        let expected = [200u32, 500, 400];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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

        // insert that will use a free cell
        inventory.insert(&mut deps.storage, 600, true).unwrap();
        assert_eq!(inventory.info.count, 4);
        assert_eq!(inventory.info.top, 4);
        assert_eq!(inventory.info.free, None);

        let expected = [600u32, 200, 500, 400];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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

        // insert at top
        inventory.insert(&mut deps.storage, 700, true).unwrap();
        // try duplicate
        inventory.insert(&mut deps.storage, 700, true).unwrap();
        assert_eq!(inventory.info.count, 5);
        assert_eq!(inventory.info.top, 5);
        assert_eq!(inventory.info.free, None);

        let expected = [600u32, 200, 500, 400, 700];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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

        assert_eq!(inventory.info.count, 4);
        assert_eq!(inventory.info.top, 5);
        assert_eq!(inventory.info.free, Some(0));

        let expected = [200u32, 500, 400, 700];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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

        let mut inventory = Inventory::new(&deps.storage, alice_raw.clone()).unwrap();

        assert_eq!(inventory.info.count, 0);
        assert_eq!(inventory.info.top, 5);
        assert_eq!(inventory.info.free, Some(3));
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

        assert_eq!(inventory.info.count, 6);
        assert_eq!(inventory.info.top, 6);
        assert_eq!(inventory.info.free, None);

        let expected = [1200u32, 900, 1000, 800, 1100, 1300];
        let mut expected_set: HashSet<u32> = HashSet::new();
        expected_set.extend(&expected);
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
        let expected = [900u32, 1000, 800, 1100, 1300];
        // verify InventoryIter
        let mut iter =
            InventoryIter::start_after(&deps.storage, &inventory, 1200, "No Error").unwrap();
        let mut iter_vec = Vec::new();
        while let Some(i) = iter.next(&deps.storage).unwrap() {
            iter_vec.push(i);
        }
        assert_eq!(iter_vec, expected);

        // test start after a middle element
        let expected = [800u32, 1100, 1300];
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
            Some(StdError::GenericErr {
                msg: "Expect Error".to_string(),
                backtrace: None
            })
        );
    }
}
