use crate::prelude::*;
use lazy_static::lazy_static;
use rand::RngCore;
use secp256k1::{Message, Secp256k1, SecretKey, SignOnly};
use std::mem::size_of;

lazy_static! {
    static ref SIGNER: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

type Range = std::ops::Range<usize>;

const fn next_range<T>(prev: Range) -> Range {
    prev.end..prev.end + size_of::<T>()
}

// Keep track of the offsets to index the data in an array.
// I'm really happy with how this turned out to make book-keeping easier.
// A macro might make this better though.
const ALLOCATION_ID_RANGE: Range = next_range::<Address>(0..0);
const PAYMENT_AMOUNT_RANGE: Range = next_range::<U256>(ALLOCATION_ID_RANGE);
const RECEIPT_ID_RANGE: Range = next_range::<Bytes16>(PAYMENT_AMOUNT_RANGE);
const SIGNATURE_RANGE: Range = next_range::<[u8; 65]>(RECEIPT_ID_RANGE);
const UNLOCKED_PAYMENT_RANGE: Range = next_range::<U256>(SIGNATURE_RANGE);
pub const BORROWED_RECEIPT_LEN: usize = UNLOCKED_PAYMENT_RANGE.end;

/// A collection of installed allocation that can borrow or generate receipts.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct ReceiptPool {
    allocations: Vec<Allocation>,
}

/// A in-flight state for an allocation on-chain.
// This must never implement Clone
#[derive(Debug, PartialEq, Eq)]
struct Allocation {
    /// Receipts that can be folded. These contain an unbroken chain
    /// of agreed upon history between the Indexer and Gateway.
    receipt_cache: Vec<PooledReceipt>,
    /// Signer: Signs the receipts. Each allocation must have a globally unique ppk pair.
    /// If keys are shared across multiple allocations it will allow the Indexer to
    /// double-collect
    signer: SecretKey,
    allocation_id: Address,
}

#[derive(PartialEq, Eq, Debug)]
pub struct ReceiptBorrow {
    /// The actual data that would unlock the payment.
    /// Because of JS interop this also includes some extra metadata
    pub commitment: Vec<u8>,
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum QueryStatus {
    Success,
    Failure,
    Unknown,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct PooledReceipt {
    pub unlocked_payment: U256,
    pub receipt_id: Bytes16,
}

#[derive(Eq, PartialEq, Debug)]
pub enum BorrowFail {
    NoAllocation,
}

impl ReceiptPool {
    pub fn new() -> Self {
        Self {
            allocations: Vec::new(),
        }
    }

    /// This is only a minimum bound, and doesn't count
    /// outstanding/forgotten receipts which may have account for a
    /// large amount of unlocked payments
    #[cfg(test)]
    pub fn known_unlocked_payments(&self) -> U256 {
        let mut result = U256::zero();
        for payment in self
            .allocations
            .iter()
            .flat_map(|a| &a.receipt_cache)
            .map(|r| r.unlocked_payment)
        {
            result += payment;
        }
        result
    }

    pub fn add_allocation(&mut self, signer: SecretKey, allocation_id: Address) {
        // Defensively ensure we don't already have this allocation.
        for allocation in self.allocations.iter() {
            if allocation.allocation_id == allocation_id {
                return;
            }
        }

        let allocation = Allocation {
            signer,
            receipt_cache: Vec::new(),
            allocation_id,
        };
        self.allocations.push(allocation)
    }

    pub fn remove_allocation(&mut self, allocation_id: &Address) {
        if let Some(index) = self
            .allocations
            .iter()
            .position(|a| &a.allocation_id == allocation_id)
        {
            self.allocations.swap_remove(index);
        }
    }

    fn select_allocation(&mut self) -> Result<&mut Allocation, BorrowFail> {
        // Prefer the one most recently added
        self.allocations.last_mut().ok_or(BorrowFail::NoAllocation)
    }

    fn allocation_by_id_mut(&mut self, allocation_id: &Address) -> Option<&mut Allocation> {
        self.allocations
            .iter_mut()
            .find(|a| &a.allocation_id == allocation_id)
    }

    pub fn commit(&mut self, locked_payment: U256) -> Result<ReceiptBorrow, BorrowFail> {
        let allocation = self.select_allocation()?;

        let receipt = if allocation.receipt_cache.len() == 0 {
            let mut receipt_id = Bytes16::default();
            rng().fill_bytes(&mut receipt_id);
            PooledReceipt {
                receipt_id,
                unlocked_payment: U256::zero(),
            }
        } else {
            let receipts = &mut allocation.receipt_cache;
            let index = rng().gen_range(0..receipts.len());
            receipts.swap_remove(index)
        };

        // Technically we don't need the mutable borrow from here on out.
        // If we ever need to unlock more concurency when these are locked
        // it would be possible to split out the remainder of this method.

        // Write the data in the official receipt that gets sent over the wire.
        // This is: [allocation_id, payment_amount, receipt_id, signature]
        let mut commitment = Vec::with_capacity(BORROWED_RECEIPT_LEN);
        let payment_amount = receipt.unlocked_payment + locked_payment;
        commitment.extend_from_slice(&allocation.allocation_id);
        commitment.extend_from_slice(&to_be_bytes(payment_amount));
        commitment.extend_from_slice(&receipt.receipt_id);

        // Engineering in any kind of replay protection like as afforded by EIP-712 is
        // unnecessary, because the signer key needs to be unique per app. It is a straightforward
        // extension from there to also say that the signer key should be globally unique and
        // not sign any messages that are not for the app. Since there are no other structs
        // to sign, there are no possible collisions.
        //
        // The part of the message that needs to be signed in the payment amount and receipt id only.
        let signed_data = &commitment[PAYMENT_AMOUNT_RANGE.start..RECEIPT_ID_RANGE.end];
        let message = Message::from_slice(&hash_bytes(signed_data)).unwrap();

        let signature = SIGNER.sign_recoverable(&message, &allocation.signer);
        let (recovery_id, signature) = signature.serialize_compact();
        let recovery_id = match recovery_id.to_i32() {
            0 => 27,
            1 => 28,
            27 => 27,
            28 => 28,
            _ => panic!("Invalid recovery id"),
        };
        commitment.extend_from_slice(&signature);
        commitment.push(recovery_id);

        // Extend with the unlocked payment, which is necessary to return collateral
        // in the case of failure.
        commitment.extend_from_slice(&to_be_bytes(receipt.unlocked_payment));

        debug_assert_eq!(BORROWED_RECEIPT_LEN, commitment.len());

        Ok(ReceiptBorrow { commitment })
    }

    pub fn release(&mut self, bytes: &[u8], status: QueryStatus) {
        assert_eq!(bytes.len(), BORROWED_RECEIPT_LEN);
        let allocation_id: Address = bytes[ALLOCATION_ID_RANGE].try_into().unwrap();

        // Try to find the allocation. If there is no allocation, it means it's been uninstalled.
        // In that case, drop the receipt.
        let allocation = if let Some(allocation) = self.allocation_by_id_mut(&allocation_id) {
            allocation
        } else {
            return;
        };

        let unlocked_payment = if status == QueryStatus::Success {
            U256::from_big_endian(&bytes[PAYMENT_AMOUNT_RANGE])
        } else {
            U256::from_big_endian(&bytes[UNLOCKED_PAYMENT_RANGE])
        };

        let receipt = PooledReceipt {
            unlocked_payment,
            receipt_id: bytes[RECEIPT_ID_RANGE].try_into().unwrap(),
        };
        allocation.receipt_cache.push(receipt);
    }
}

fn to_be_bytes(value: U256) -> Bytes32 {
    let mut result = Bytes32::default();
    value.to_big_endian(&mut result);
    result
}

fn hash_bytes(bytes: &[u8]) -> Bytes32 {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Keccak::v256();
    hasher.update(&bytes);
    let mut output = Bytes32::default();
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[track_caller]
    fn assert_failed_borrow(pool: &mut ReceiptPool, amount: impl Into<U256>) {
        let receipt = pool.commit(amount.into());
        assert_eq!(receipt, Err(BorrowFail::NoAllocation));
    }

    #[track_caller]
    fn assert_successful_borrow(pool: &mut ReceiptPool, amount: impl Into<U256>) -> Vec<u8> {
        pool.commit(U256::from(amount.into()))
            .expect("Should be able to borrow")
            .commitment
    }

    // Simple happy-path case of paying for requests in a loop.
    #[test]
    pub fn can_pay_for_requests() {
        let mut pool = ReceiptPool::new();
        pool.add_allocation(test_signer(), bytes(1));

        for i in 1..=10 {
            let borrow = assert_successful_borrow(&mut pool, i);
            pool.release(&borrow, QueryStatus::Success);
            // Verify that we have unlocked all the payments
            let unlocked: u32 = (0..=i).sum();
            assert_eq!(U256::from(unlocked), pool.known_unlocked_payments());
        }
    }

    #[test]
    pub fn selects_allocation() {
        let mut pool = ReceiptPool::new();

        pool.add_allocation(test_signer(), bytes(1));
        pool.add_allocation(test_signer(), bytes(2));
        pool.add_allocation(test_signer(), bytes(3));
        pool.add_allocation(test_signer(), bytes(4));
        pool.add_allocation(test_signer(), bytes(5));
        pool.add_allocation(test_signer(), bytes(6));
        pool.add_allocation(test_signer(), bytes(7));
        pool.add_allocation(test_signer(), bytes(8));

        assert_successful_borrow(&mut pool, 2);
        assert_successful_borrow(&mut pool, 4);
        assert_successful_borrow(&mut pool, 3);
        assert_successful_borrow(&mut pool, 1);
        assert_successful_borrow(&mut pool, 2);
        assert_successful_borrow(&mut pool, 3);
        assert_successful_borrow(&mut pool, 1);
        assert_successful_borrow(&mut pool, 4);
    }

    // Any uninstalled allocation cannot be used to pay for queries.
    #[test]
    fn removed_allocation_cannot_pay() {
        let mut pool = ReceiptPool::new();
        pool.add_allocation(test_signer(), bytes(2));
        pool.add_allocation(test_signer(), bytes(1));

        pool.remove_allocation(&bytes(2));
        assert_successful_borrow(&mut pool, 5);
        pool.remove_allocation(&bytes(1));
        assert_failed_borrow(&mut pool, 5);
    }

    // Tests modes for returning collateral
    #[test]
    fn collateral_return() {
        let mut pool = ReceiptPool::new();

        pool.add_allocation(test_signer(), bytes(2));

        let borrow3 = assert_successful_borrow(&mut pool, 3);
        assert_eq!(pool.known_unlocked_payments(), 0.into());

        let borrow2 = assert_successful_borrow(&mut pool, 2);
        assert_eq!(pool.known_unlocked_payments(), 0.into());

        pool.release(&borrow3, QueryStatus::Failure);
        assert_eq!(pool.known_unlocked_payments(), 0.into());

        let borrow4 = assert_successful_borrow(&mut pool, 4);
        assert_eq!(pool.known_unlocked_payments(), 0.into());

        pool.release(&borrow2, QueryStatus::Success);
        assert_eq!(pool.known_unlocked_payments(), 2.into());

        pool.release(&borrow4, QueryStatus::Unknown);
        assert_eq!(pool.known_unlocked_payments(), 2.into());
    }
}
