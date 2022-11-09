use lazy_static::lazy_static;
use secp256k1::{Message, Secp256k1, SecretKey};
use std::{fmt, mem::size_of};
pub use {
    primitive_types::U256,
    rand::{thread_rng as rng, Rng as _},
    std::convert::TryInto as _,
};

pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
// This can't be [u8; 16] because then the length would collide with the
// transfer implementation which uses Bytes32 (TransferId) + u32 (ReceiptId) = 36 bytes
// and this would have been Address (AllocationId) + 16 = 36 bytes.
pub type ReceiptId = [u8; 15];
pub type Signature = [u8; 65];

pub type Range = std::ops::Range<usize>;

pub const fn next_range<T>(prev: Range) -> Range {
    prev.end..prev.end + size_of::<T>()
}

lazy_static! {
    pub static ref SECP256K1: Secp256k1<secp256k1::All> = Secp256k1::new();
}

pub fn hash_bytes(bytes: &[u8]) -> Bytes32 {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&bytes);
    let mut output = Bytes32::default();
    hasher.finalize(&mut output);
    output
}

pub fn to_be_bytes(value: U256) -> Bytes32 {
    let mut result = Bytes32::default();
    value.to_big_endian(&mut result);
    result
}

#[derive(Eq, PartialEq, Debug)]
pub enum SignError {
    InvalidRecoveryId,
}

impl fmt::Display for SignError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Invalid recovery ID")
    }
}

pub fn sign(data: &[u8], signer: &SecretKey) -> Result<Signature, SignError> {
    let message = Message::from_slice(&hash_bytes(data)).unwrap();

    let signature = SECP256K1.sign_ecdsa_recoverable(&message, signer);
    let (recovery_id, signature) = signature.serialize_compact();
    let recovery_id = match recovery_id.to_i32() {
        0 => 27,
        1 => 28,
        27 => 27,
        28 => 28,
        _ => return Err(SignError::InvalidRecoveryId),
    };

    let mut serialized = [0; 65];
    (&mut serialized[..64]).copy_from_slice(&signature);
    serialized[64] = recovery_id;

    Ok(serialized)
}
