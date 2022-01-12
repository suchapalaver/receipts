use crate::prelude::*;
use itertools::Itertools as _;
use secp256k1::{Message, PublicKey, SecretKey};
use std::fmt;
use tiny_keccak::{Hasher, Keccak};

#[derive(Debug)]
pub enum VoucherError {
    InvalidData,
    InvalidSignature,
    UnorderedReceipts,
    UnorderedPartialVouchers,
    NoValue,
}

impl std::error::Error for VoucherError {}

impl fmt::Display for VoucherError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidData => write!(f, "Invalid receipts data"),
            Self::InvalidSignature => write!(f, "Receipts are not signed for the given allocation"),
            Self::UnorderedReceipts => write!(f, "Unordered receipts"),
            Self::UnorderedPartialVouchers => write!(f, "Unordered partial vouchers"),
            Self::NoValue => write!(f, "Receipts have no value"),
        }
    }
}

const FEE_RANGE: Range = next_range::<U256>(0..0);
const RECEIPT_ID_RANGE: Range = next_range::<ReceiptId>(FEE_RANGE);
const SIGNATURE_RANGE: Range = next_range::<Signature>(RECEIPT_ID_RANGE);
const SIZE: usize = SIGNATURE_RANGE.end; // 112 bytes, last I checked.

struct Receipts<'r> {
    pub data: &'r [u8],
    pub index: usize,
}

struct Receipt<'r> {
    pub fees: U256,
    pub id: &'r ReceiptId,
    pub signature: &'r Signature,
}

impl Receipts<'_> {
    fn new(data: &[u8]) -> Result<Receipts, VoucherError> {
        if data.len() % SIZE != 0 {
            return Err(VoucherError::InvalidData);
        }
        Ok(Receipts { data, index: 0 })
    }
}

impl<'r> Iterator for Receipts<'r> {
    type Item = Receipt<'r>;
    fn next(&mut self) -> Option<Self::Item> {
        if (self.index * SIZE) >= self.data.len() {
            return None;
        }
        let chunk = &self.data[(self.index * SIZE)..];
        self.index += 1;
        Some(Receipt {
            fees: U256::from_big_endian(&chunk[FEE_RANGE]),
            id: (&chunk[RECEIPT_ID_RANGE]).try_into().unwrap(),
            signature: (&chunk[SIGNATURE_RANGE]).try_into().unwrap(),
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct Voucher {
    pub allocation_id: Address,
    pub fees: U256,
    pub signature: Signature,
}

pub struct PartialVoucher {
    pub voucher: Voucher,
    pub receipt_id_min: ReceiptId,
    pub receipt_id_max: ReceiptId,
}

/// Security: The voucher_signer must be dedicated to this purpose, hold no funds,
/// and sign no other messages except with this method. Similarly, the allocation
/// signer must only sign allocations and serve no other purpose and hold no funds.
/// One exception is that they may be the same signer. They are allowed to be different
/// in case we want to rotate the voucher_signer and keep old receipts intact. Having
/// them be the same signer is ok only because they sign messages of different lengths.

pub fn receipts_to_voucher(
    allocation_id: &Address,
    allocation_signer: &PublicKey,
    voucher_signer: &SecretKey,
    data: &[u8],
) -> Result<Voucher, VoucherError> {
    let fees = verify_receipts(allocation_id, allocation_signer, data)?;
    let mut message = Vec::new();
    message.extend_from_slice(allocation_id);
    message.extend_from_slice(&to_be_bytes(fees));
    Ok(Voucher {
        allocation_id: *allocation_id,
        fees,
        signature: sign(&message, voucher_signer),
    })
}

pub fn receipts_to_partial_voucher(
    allocation_id: &Address,
    allocation_signer: &PublicKey,
    voucher_signer: &SecretKey,
    data: &[u8],
) -> Result<PartialVoucher, VoucherError> {
    let fees = verify_receipts(allocation_id, allocation_signer, data)?;
    let receipt_id_min = *Receipts::new(data)?.next().unwrap().id;
    let receipt_id_max = *Receipts::new(data)?.last().unwrap().id;
    let mut message = Vec::new();
    message.extend_from_slice(allocation_id);
    message.extend_from_slice(&to_be_bytes(fees));
    message.extend_from_slice(&receipt_id_min);
    message.extend_from_slice(&receipt_id_max);
    Ok(PartialVoucher {
        voucher: Voucher {
            allocation_id: *allocation_id,
            fees,
            signature: sign(&message, voucher_signer),
        },
        receipt_id_min,
        receipt_id_max,
    })
}

fn verify_receipts(
    allocation_id: &Address,
    allocation_signer: &PublicKey,
    data: &[u8],
) -> Result<U256, VoucherError> {
    // Verify the receipts are sorted and ascending.
    // This also verifies their uniqueness.
    if Receipts::new(data)?
        .map(|receipt| *receipt.id)
        .tuple_windows()
        .any(|(a, b)| !(a < b))
    {
        return Err(VoucherError::UnorderedReceipts);
    }

    // Verify signatures
    for receipt in Receipts::new(data)? {
        // Create the signed message from the receipt data.
        // Allocationid is "untrusted" and kept separate from the receipt data.
        // This also de-duplicates it in the message.
        let mut hasher = Keccak::v256();
        hasher.update(allocation_id);
        hasher.update(&to_be_bytes(receipt.fees));
        hasher.update(receipt.id);
        let mut message = Bytes32::default();
        hasher.finalize(&mut message);

        let message = Message::from_slice(&message).unwrap();
        let signature = secp256k1::Signature::from_compact(&receipt.signature[..64])
            .map_err(|_| VoucherError::InvalidData)?;
        SECP256K1
            .verify(&message, &signature, allocation_signer)
            .map_err(|_| VoucherError::InvalidSignature)?;
    }

    let fees = Receipts::new(data)?
        .map(|receipt| receipt.fees)
        .fold(U256::zero(), |sum, fees| sum.saturating_add(fees));
    // The contract will revert if this is 0
    if fees == U256::zero() {
        return Err(VoucherError::NoValue);
    }
    Ok(fees)
}

pub fn combine_partial_vouchers(
    allocation_id: &Address,
    voucher_signer: &SecretKey,
    partial_vouchers: &[PartialVoucher],
) -> Result<Voucher, VoucherError> {
    if partial_vouchers.len() == 0 {
        return Err(VoucherError::NoValue);
    }

    // Check that receipt ID ranges are ordered and non-overlapping.
    // This is done by checking that for a sliding window of range limits:
    //   forall (a0, a1), (b0, b1): a0 < a1 < b0 < b1
    if !partial_vouchers
        .iter()
        .flat_map(|pv| [pv.receipt_id_min, pv.receipt_id_max])
        .tuple_windows()
        .all(|(a, b)| a < b)
    {
        return Err(VoucherError::UnorderedPartialVouchers);
    }

    // Verify signatures
    let partial_voucher_signer = PublicKey::from_secret_key(&SECP256K1, &voucher_signer);
    for partial_voucher in partial_vouchers {
        let mut hasher = Keccak::v256();
        hasher.update(allocation_id);
        hasher.update(&to_be_bytes(partial_voucher.voucher.fees));
        hasher.update(&partial_voucher.receipt_id_min);
        hasher.update(&partial_voucher.receipt_id_max);
        let mut message = Bytes32::default();
        hasher.finalize(&mut message);

        let message = Message::from_slice(&message).unwrap();
        let signature =
            secp256k1::Signature::from_compact(&partial_voucher.voucher.signature[..64])
                .map_err(|_| VoucherError::InvalidData)?;
        SECP256K1
            .verify(&message, &signature, &partial_voucher_signer)
            .map_err(|_| VoucherError::InvalidSignature)?;
    }

    let fees = partial_vouchers
        .iter()
        .map(|pv| pv.voucher.fees)
        .fold(U256::zero(), |sum, fees| sum.saturating_add(fees));
    if fees == U256::zero() {
        return Err(VoucherError::NoValue);
    }

    // Create signature for complete voucher
    let mut message = Vec::new();
    message.extend_from_slice(allocation_id);
    message.extend_from_slice(&to_be_bytes(fees));
    let signature = sign(&message, voucher_signer);

    Ok(Voucher {
        allocation_id: *allocation_id,
        fees,
        signature,
    })
}

#[cfg(feature = "use-neon")]
use neon::prelude::*;
#[cfg(feature = "use-neon")]
use neon_utils::{
    errors::{IntoError, SafeJsResult},
    js_object,
    marshalling::IntoHandle,
};

#[cfg(feature = "use-neon")]
impl IntoError for VoucherError {
    fn into_error<'c>(&self, cx: &mut impl Context<'c>) -> JsResult<'c, JsError> {
        let display = format!("{}", self);
        display.into_error(cx)
    }
}

#[cfg(feature = "use-neon")]
impl IntoHandle for Voucher {
    type Handle = JsObject;
    fn into_handle<'c>(&self, cx: &mut impl Context<'c>) -> SafeJsResult<'c, Self::Handle> {
        js_object!(cx => {
            allocation: &self.allocation_id,
            amount: &self.fees,
            signature: &self.signature.to_vec(),
        })
    }
}
