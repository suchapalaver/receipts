use crate::prelude::*;
use eip_712_derive::DomainSeparator;
use lazy_static::lazy_static;
use secp256k1::{Message, Secp256k1, SecretKey, SignOnly};

lazy_static! {
    static ref SIGNER: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

fn to_le_bytes(value: U256) -> Bytes32 {
    let mut result = Bytes32::default();
    value.to_little_endian(&mut result);
    result
}

fn hash_bytes(domain_separator: &Bytes32, bytes: &[u8]) -> Bytes32 {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Sha3::v256();
    hasher.update(&domain_separator[..]);
    hasher.update(&bytes);
    let mut output = Bytes32::default();
    hasher.finalize(&mut output);
    output
}

// Writes out bytes which can unlock a payment in the borrowed receipt,
// as well as some metadata to return the borrowed receipt. This second part wouldn't be
// necessary except that we are moving the BorrowedReceipt out of Rust into JavaScript.
pub fn serialize_payment_commitment_and_borrow(
    borrow: BorrowedReceipt,
    secret_key: &SecretKey,
    domain: &DomainSeparator,
    dest: &mut Vec<u8>,
) {
    payment_commitment(&borrow, secret_key, domain, dest);
    dest.extend_from_slice(&to_le_bytes(borrow.locked_payment));
}

// Recreates the BorrowedReceipt struct from the serialized representation
pub fn deserialize_borrow_from_commitment_and_borrow(bytes: &[u8]) -> BorrowedReceipt {
    assert_eq!(bytes.len(), 176);
    let vector_app_id: Bytes32 = bytes[0..32].try_into().unwrap();
    let payment_amount = U256::from_little_endian(&bytes[32..64]);
    let receipt_id: Bytes16 = bytes[64..80].try_into().unwrap();
    // signature: [80..144]
    let locked_payment = U256::from_little_endian(&bytes[144..176]);
    let unlocked_payment = payment_amount - locked_payment;

    BorrowedReceipt {
        vector_app_id,
        locked_payment,
        pooled_receipt: PooledReceipt {
            unlocked_payment,
            receipt_id,
        },
    }
}

// Writes out bytes which can unlock a payment in the borrowed receipt.
fn payment_commitment(
    borrow: &BorrowedReceipt,
    secret_key: &SecretKey,
    domain: &DomainSeparator,
    dest: &mut Vec<u8>,
) {
    // Write the data in the official receipt that gets sent over the wire.
    // This is: [vector_app_id, payment_amount, receipt_id, signature]
    // That this math does not overflow is checked when we borrow the receipt.
    let payment_amount = borrow.locked_payment + borrow.pooled_receipt.unlocked_payment;
    dest.extend_from_slice(&borrow.vector_app_id);
    dest.extend_from_slice(&to_le_bytes(payment_amount));
    dest.extend_from_slice(&borrow.pooled_receipt.receipt_id);

    // This is diverging from EIP-712 for a couple of reasons. The main reason
    // is that EIP-712 unnecessarily uses extra hashes. Even in the best case
    // EIP-712 requires 2 hashes. When variable length data is involved, there
    // are even more hashes (which is not the most performant way to disambiguate,
    // which is what they are accomplishing). So, just taking the best parts
    // of EIP-712 here to prevent replay attacks by using a DomainSeparator. We
    // could use a struct definition too, but since we have only one struct that's not
    // necessary either.
    let message = Message::from_slice(&hash_bytes(domain.as_bytes(), &dest)).unwrap();
    let signature = SIGNER.sign(&message, secret_key);
    dest.extend_from_slice(&signature.serialize_compact());
}

#[cfg(test)]
mod tests {
    use crate::prelude::*;
    use crate::tests::*;
    #[test]
    fn round_trip() {
        let mut pool = ReceiptPool::new();
        pool.add_app(bytes32(1), U256::from(10000));
        let (secret_key, domain_separator) = test_sign_data();

        let borrow = pool.borrow(U256::from(199)).unwrap();
        let check = borrow.clone();
        let mut ser = Vec::new();
        serialize_payment_commitment_and_borrow(borrow, &secret_key, &domain_separator, &mut ser);
        let de = deserialize_borrow_from_commitment_and_borrow(&ser);

        assert_eq!(check, de);
    }
}
