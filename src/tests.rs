use crate::pool::*;
use crate::prelude::*;
use secp256k1::SecretKey;
use std::time::Instant;

pub fn bytes32(id: u8) -> Bytes32 {
    let mut result = Bytes32::default();
    result[0] = id;
    result
}

pub fn test_signer() -> SecretKey {
    // Generated online somewhere. This is a test key with no funds
    "244226452948404D635166546A576E5A7234753778217A25432A462D4A614E64"
        .parse()
        .unwrap()
}

#[test]
#[ignore = "This panics to output the result time. Should use a proper benchmarking lib."]
fn speed() {
    let mut pool = ReceiptPool::new();
    pool.add_transfer(test_signer(), U256::from(10000), bytes32(0));
    pool.add_transfer(test_signer(), U256::from(1000000000), bytes32(1));

    let mut borrows = Vec::<Vec<u8>>::new();

    let start = Instant::now();

    for _ in 0..2700 {
        for _ in 0..10 {
            let commitment = pool.commit(U256::from(100)).unwrap().commitment;
            borrows.push(commitment)
        }
        while let Some(borrow) = borrows.pop() {
            pool.release(&borrow, QueryStatus::Success)
        }
    }

    let end = Instant::now();

    panic!("{:?}", end - start);
}
