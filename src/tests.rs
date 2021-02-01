use crate::pool::*;
use crate::prelude::*;
use eip_712_derive::{chain_id::GETH_PRIVATE_DEFAULT, Address};
use std::time::Instant;

fn address(id: u8) -> [u8; 20] {
    let mut result = <[u8; 20]>::default();
    result[0] = id;
    result
}

pub fn test_keys(id: u8) -> Keys {
    Keys {
        secret: "244226452948404D635166546A576E5A7234753778217A25432A462D4A614E64"
            .parse()
            .unwrap(),
        address: address(id),
        domain: crate::domain_separator(GETH_PRIVATE_DEFAULT, Address(address(0))),
    }
}

#[test]
#[ignore = "This panics to output the result time. Should use a proper benchmarking lib."]
fn speed() {
    let mut pool = ReceiptPool::new();
    pool.add_app(test_keys(0), U256::from(10000));
    pool.add_app(test_keys(1), U256::from(1000000000));

    let mut borrows = Vec::<Vec<u8>>::new();

    let start = Instant::now();

    for _ in 0..2300 {
        for _ in 0..10 {
            let commitment = pool.commit(U256::from(100)).unwrap();
            borrows.push(commitment)
        }
        while let Some(borrow) = borrows.pop() {
            pool.release(&borrow, QueryStatus::Success)
        }
    }

    let end = Instant::now();

    panic!("{:?}", end - start);
}
