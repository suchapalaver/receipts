use crate::pool::*;
use crate::prelude::*;
use secp256k1::SecretKey;
use std::time::Instant;

pub fn bytes32(id: u8) -> Bytes32 {
    let mut result = Bytes32::default();
    result[0] = id;
    result
}

fn debug_hex(bytes: &[u8]) {
    use rustc_hex::ToHex as _;
    let hex: String = bytes.to_hex();
    println!("{}", hex);
}

// This is just useful for constructing a value to test with.
#[test]
pub fn make_receipt() {
    let mut pool = ReceiptPool::new();
    let signer = test_signer();
    let s = secp256k1::Secp256k1::signing_only();
    let public = secp256k1::PublicKey::from_secret_key(&s, &signer);

    let mut transfer_id = Bytes32::default();
    transfer_id[0] = 100;
    let collateral = U256::from(200);
    pool.add_transfer(signer, collateral, transfer_id);

    let commit = pool.commit(U256::from(5)).unwrap();

    debug_hex(&commit.commitment);

    println!("{}", public);
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
