use std::{convert::TryFrom, time::Instant};

use secp256k1::{PublicKey, SecretKey};

use crate::{prelude::*, *};

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
    let mut pool = ReceiptPool::new(bytes(100));

    println!("Receipt 0: value 5");
    let commit0 = pool.commit(&test_signer(), U256::from(5)).unwrap();
    debug_hex(&commit0);

    println!("Receipt 1: value 8");
    let commit1 = pool.commit(&test_signer(), U256::from(8)).unwrap();
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
#[ignore = "Benchmark"]
fn speed() {
    let mut pool = ReceiptPool::new(bytes(0));

    let mut borrows = Vec::<Vec<u8>>::new();

    let start = Instant::now();

    for _ in 0..2700 {
        for _ in 0..10 {
            let commitment = pool.commit(&test_signer(), U256::from(100)).unwrap();
            borrows.push(commitment)
        }
        while let Some(borrow) = borrows.pop() {
            pool.release(&borrow, QueryStatus::Success)
        }
    }

    let end = Instant::now();

    dbg!("{:?}", end - start);
}

#[test]
fn attempt_to_double_collect_with_partial_voucher_rejects() {
    let allocation_id = bytes(1);

    // Create a bunch of receipts
    let mut pool = ReceiptPool::new(allocation_id);
    let mut borrows = Vec::<Vec<u8>>::new();
    for _ in 0..10 {
        let fee = U256::from(1);
        let commitment = pool.commit(&test_signer(), fee).unwrap();
        borrows.push(commitment);
    }

    let to_partial = |b| {
        let receipts = receipts_from_borrows(b);
        receipts_to_partial_voucher(
            &allocation_id,
            &PublicKey::from_secret_key(&SECP256K1, &test_signer()),
            &test_signer(),
            &receipts,
        )
        .unwrap()
    };

    let partial_1 = to_partial(borrows[5..].to_vec());
    let partial_2 = to_partial(borrows[..5].to_vec());

    for ordering in [
        vec![partial_1.clone(), partial_2.clone()],
        vec![partial_2.clone(), partial_1.clone()],
        vec![partial_1.clone(), partial_1.clone()],
    ] {
        let err = combine_partial_vouchers(&allocation_id, &test_signer(), &ordering);
        assert_eq!(err, Err(VoucherError::UnorderedPartialVouchers));
    }
}

#[test]
fn vouchers() {
    let allocation_id = bytes(1);

    // Create a bunch of receipts
    let mut pool = ReceiptPool::new(allocation_id);
    let mut borrows = Vec::<Vec<u8>>::new();
    let mut fees = U256::zero();
    for i in 2..10 {
        for borrow in borrows.drain(..) {
            pool.release(&borrow, QueryStatus::Success);
        }
        for _ in 0..i {
            let fee = U256::from(1);
            fees += fee;
            let commitment = pool.commit(&test_signer(), fee).unwrap();
            borrows.push(commitment);
        }
    }
    let receipts = receipts_from_borrows(borrows);

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
    assert_eq!(&voucher.fees, &fees);
}

#[test]
#[ignore = "Benchmark"]
fn vouchers_speed() {
    let allocation_id = bytes(1);
    let receipts = create_receipts(allocation_id, 100000);

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

#[test]
fn partial_vouchers_combine_single() {
    let allocation_id = bytes(1);
    let allocation_signer = PublicKey::from_secret_key(&SECP256K1, &test_signer());

    let receipts = create_receipts(allocation_id, 1);
    let partial_voucher = receipts_to_partial_voucher(
        &allocation_id,
        &allocation_signer,
        &test_signer(),
        &receipts,
    )
    .unwrap();
    let oneshot_receipt = receipts_to_voucher(
        &allocation_id,
        &allocation_signer,
        &test_signer(),
        &receipts,
    )
    .unwrap();
    let combined_voucher =
        combine_partial_vouchers(&allocation_id, &test_signer(), &[partial_voucher]).unwrap();
    // Warning: This is relying on an ECDSA implementation compatible with RFC 6979
    // (deterministic usage of signatures).
    assert_eq!(oneshot_receipt, combined_voucher);
}

#[test]
fn partial_vouchers_combine() {
    let allocation_id = bytes(1);
    let allocation_signer = PublicKey::from_secret_key(&SECP256K1, &test_signer());

    let create_partial_voucher = |receipts: &[u8]| -> PartialVoucher {
        receipts_to_partial_voucher(&allocation_id, &allocation_signer, &test_signer(), receipts)
            .unwrap()
    };

    let mut rng = rand::thread_rng();
    let receipt_count = rng.gen_range(2..=1000);
    let receipts = create_receipts(allocation_id, receipt_count);

    let batch_size = rng.gen_range(1..receipt_count);
    println!(
        "receipt_count: {}, batch_size: {}",
        receipt_count, batch_size,
    );
    let partial_vouchers: Vec<PartialVoucher> = receipts
        .chunks(112 * batch_size)
        .map(create_partial_voucher)
        .collect();
    let oneshot_receipt = receipts_to_voucher(
        &allocation_id,
        &allocation_signer,
        &test_signer(),
        &receipts,
    )
    .unwrap();
    let combined_voucher =
        combine_partial_vouchers(&allocation_id, &test_signer(), &partial_vouchers).unwrap();
    // Warning: This is relying on an ECDSA implementation compatible with RFC 6979
    // (deterministic usage of signatures).
    assert_eq!(oneshot_receipt, combined_voucher);
}

fn create_receipts(allocation_id: Address, count: usize) -> Vec<u8> {
    let mut pool = ReceiptPool::new(allocation_id);
    let mut borrows = Vec::<Vec<u8>>::new();
    for _ in 1..=count {
        let commitment = pool.commit(&test_signer(), U256::from(1)).unwrap();
        borrows.push(commitment);
    }
    receipts_from_borrows(borrows)
}

fn receipts_from_borrows(mut borrows: Vec<Vec<u8>>) -> Vec<u8> {
    let mut receipts = Vec::with_capacity(112 * borrows.len());
    // Sort by receipt id
    borrows.sort_by_key(|b| ReceiptId::try_from(&b[52..67]).unwrap());
    // Serialize
    for borrow in borrows {
        receipts.extend_from_slice(&borrow[20..132]);
    }
    receipts
}
