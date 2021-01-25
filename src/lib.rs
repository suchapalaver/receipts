pub mod format;
mod pool;
mod prelude;

use eip_712_derive::{Address, DomainSeparator, Eip712Domain};
pub use pool::{BorrowFail, BorrowedReceipt, QueryStatus, ReceiptPool};
use prelude::*;
use secp256k1::SecretKey;

extern crate lazy_static;

/// This exists for JS interop convenience. Some cleanup is possible if JS is removed
/// because serializing the borrow is not necessary and you only need the payment commitment.
pub fn release_payment(bytes: &[u8], pool: &mut ReceiptPool, status: QueryStatus) {
    let borrow = deserialize_borrow_from_commitment_and_borrow(&bytes);
    pool.release(borrow, status);
}

/// This exists for JS interop convenience. Some cleanup is possible if JS is removed
/// because serializing the borrow is not necessary and you only need the payment commitment.
pub fn borrow_payment_commitment(
    pool: &mut ReceiptPool,
    locked_payment: U256,
    secret_key: &SecretKey,
    domain: &DomainSeparator,
    dest: &mut Vec<u8>,
) -> Result<(), BorrowFail> {
    let borrow = pool.borrow(locked_payment)?;
    serialize_payment_commitment_and_borrow(borrow, secret_key, domain, dest);
    Ok(())
}

pub fn domain_separator(
    chain_id: eip_712_derive::U256,
    verifying_contract: Address,
) -> DomainSeparator {
    let domain = Eip712Domain {
        name: "Graph Protocol Receipts".to_owned(),
        version: "0".to_owned(),
        chain_id,
        verifying_contract,
        // Generated with rand::thread_rng()
        salt: [
            218, 74, 158, 13, 37, 78, 132, 39, 49, 55, 206, 208, 165, 164, 142, 73, 200, 0, 91, 38,
            111, 161, 92, 240, 117, 127, 92, 117, 83, 211, 150, 158,
        ],
    };

    DomainSeparator::new(&domain)
}

#[cfg(test)]
mod tests;
