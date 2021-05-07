use crate::prelude::*;
use crate::*;
use secp256k1::{PublicKey, SecretKey};
use std::convert::TryFrom;
use std::time::Instant;

pub fn bytes<const N: usize>(id: u8) -> [u8; N] {
    [id; N]
}

fn debug_hex(bytes: &[u8]) {
    use rustc_hex::ToHex as _;
    let hex: String = bytes.to_hex();
    println!("{}\n", hex);
}

// This is just useful for constructing a value to test with.
#[test]
pub fn make_receipt() {
    let mut pool = ReceiptPool::new();
    let signer = test_signer();

    pool.add_allocation(signer, bytes(100));

    println!("Receipt 0: value 5");
    let commit0 = pool.commit(U256::from(5)).unwrap();
    debug_hex(&commit0);

    println!("Receipt 1: value 8");
    let commit1 = pool.commit(U256::from(8)).unwrap();
    debug_hex(&commit1);
}

pub fn test_signer() -> SecretKey {
    // Found this online. This is a test key with no funds.
    /*
    Private key:  9d6803c0326f725338d42d580aba5e7a2d1d4b95fd602609f5e008e17f030d87
    Public key:  aecdc332a922c3d1b643ee158b9ce8529e28a5b18bbea4e4ba7e57f698b719ff9598ef3aa85866cb86abadf3df79bb6bd1d96f2595800aaf5dc3b22b70afcf3e
    Address: 0xc61127cdfb5380df4214b0200b9a07c7c49d34f9
    */
    "9d6803c0326f725338d42d580aba5e7a2d1d4b95fd602609f5e008e17f030d87"
        .parse()
        .unwrap()
}

#[test]
#[ignore = "This panics to output the result time. Should use a proper benchmarking lib."]
fn speed() {
    let mut pool = ReceiptPool::new();
    pool.add_allocation(test_signer(), bytes(0));
    pool.add_allocation(test_signer(), bytes(1));

    let mut borrows = Vec::<Vec<u8>>::new();

    let start = Instant::now();

    for _ in 0..2700 {
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

#[test]
fn vouchers() {
    let allocation_id = bytes(1);

    // Create a bunch of receipts
    let mut pool = ReceiptPool::new();
    pool.add_allocation(test_signer(), allocation_id);
    let mut borrows = Vec::<Vec<u8>>::new();

    let mut total = U256::zero();
    for i in 2..10 {
        for borrow in borrows.drain(..) {
            pool.release(&borrow, QueryStatus::Success);
        }
        for _ in 0..i {
            let amount = U256::from(1);
            total += amount;
            let commitment = pool.commit(amount).unwrap();
            borrows.push(commitment);
        }
    }

    let mut receipts = Vec::with_capacity(112 * borrows.len());

    // Sort by receipt id
    borrows.sort_by_key(|b| ReceiptId::try_from(&b[52..67]).unwrap());

    // Serialize
    for borrow in borrows.iter() {
        receipts.extend_from_slice(&borrow[20..132]);
    }

    // Convert to voucher
    let allocation_signer = PublicKey::from_secret_key(&SECP256K1, &test_signer());

    let voucher = receipts_to_voucher(
        &allocation_id,
        &allocation_signer,
        &test_signer(),
        &receipts,
    )
    .unwrap();

    assert_eq!(&voucher.allocation_id, &allocation_id);
    assert_eq!(&voucher.amount, &total);
}

#[test]
#[ignore = "Benchmark"]
fn vouchers_speed() {
    let allocation_id = bytes(1);

    // Create a bunch of receipts
    let mut pool = ReceiptPool::new();
    pool.add_allocation(test_signer(), allocation_id);
    let mut borrows = Vec::<Vec<u8>>::new();

    for _ in 1..100000 {
        let commitment = pool.commit(U256::from(1)).unwrap();
        borrows.push(commitment);
    }

    let mut receipts = Vec::with_capacity(112 * borrows.len());

    // Sort by receipt id
    borrows.sort_by_key(|b| ReceiptId::try_from(&b[52..67]).unwrap());

    // Serialize
    for borrow in borrows.iter() {
        receipts.extend_from_slice(&borrow[20..132]);
    }

    // Convert to voucher
    let allocation_signer = PublicKey::from_secret_key(&SECP256K1, &test_signer());

    let start = Instant::now();
    receipts_to_voucher(
        &allocation_id,
        &allocation_signer,
        &test_signer(),
        &receipts,
    )
    .unwrap();

    let end = Instant::now();

    dbg!(end - start);
}
