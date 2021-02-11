use crate::prelude::*;
use lazy_static::lazy_static;
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
const VECTOR_TRANSFER_ID_RANGE: Range = next_range::<Bytes32>(0..0);
const PAYMENT_AMOUNT_RANGE: Range = next_range::<U256>(VECTOR_TRANSFER_ID_RANGE);
const RECEIPT_ID_RANGE: Range = next_range::<ReceiptID>(PAYMENT_AMOUNT_RANGE);
const SIGNATURE_RANGE: Range = next_range::<[u8; 65]>(RECEIPT_ID_RANGE);
const UNLOCKED_PAYMENT_RANGE: Range = next_range::<U256>(SIGNATURE_RANGE);
pub const BORROWED_RECEIPT_LEN: usize = UNLOCKED_PAYMENT_RANGE.end;

/// A collection of installed transfers that can borrow or generate receipts.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct ReceiptPool {
    transfers: Vec<Transfer>,
}

/// A in-flight state for a transfer that has been initiated using Vector.
// This must never implement Clone
#[derive(Debug, PartialEq, Eq)]
struct Transfer {
    /// There is no need to sync the collateral to the db. If we crash, should
    /// either rotate out transfers or recover the transfer state from the Indexer.
    collateral: U256,
    /// The ZKP is most efficient when using receipts from a contiguous range
    /// as this allows the receipts to be constants rather than witnessed-in,
    /// and also have preset data sizes for amortized proving time.
    prev_receipt_id: ReceiptID,
    /// Receipts that can be folded. These contain an unbroken chain
    /// of agreed upon history between the Indexer and Gateway.
    receipt_cache: Vec<PooledReceipt>,
    /// Signer: Signs the receipts. Each transfer must have a globally unique ppk pair.
    /// If keys are shared across multiple Transfers it will allow the Indexer to
    /// double-collect the same receipt across multiple transfers
    signer: SecretKey,
    /// The address should be enough to uniquely identify a transfer,
    /// since the security model of the Consumer relies on having a unique
    /// address for each transfer. But, there's nothing preventing a Consumer
    /// from putting themselves at risk - which opens up some interesting
    /// greifing attacks. It just makes it simpler therefore to use the transfer
    /// id to key the receipt and lookup the address rather than lookup all transfers
    /// matching an address. Unlike the address which is specified by the Consumer,
    /// the transfer id has a unique source of truth - the Vector node.
    vector_transfer_id: Bytes32,
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
    pub receipt_id: ReceiptID,
}

#[derive(Eq, PartialEq, Debug)]
pub enum BorrowFail {
    // If this error is encountered it means that a new transfer with
    // more collateral must be installed.
    InsufficientCollateral,
}

impl ReceiptPool {
    pub fn new() -> Self {
        Self {
            transfers: Vec::new(),
        }
    }

    /// This is only a minimum bound, and doesn't count
    /// outstanding/forgotten receipts which may have account for a
    /// large amount of unlocked payments
    #[cfg(test)]
    pub fn known_unlocked_payments(&self) -> U256 {
        let mut result = U256::zero();
        for payment in self
            .transfers
            .iter()
            .flat_map(|a| &a.receipt_cache)
            .map(|r| r.unlocked_payment)
        {
            result += payment;
        }
        result
    }

    pub fn add_transfer(
        &mut self,
        signer: SecretKey,
        collateral: U256,
        vector_transfer_id: Bytes32,
    ) {
        // Defensively ensure we don't already have this transfer.
        // Note that the collateral may not match, but that would be ok.
        for transfer in self.transfers.iter() {
            if transfer.vector_transfer_id == vector_transfer_id {
                return;
            }
        }
        let transfer = Transfer {
            signer,
            collateral,
            receipt_cache: Vec::new(),
            prev_receipt_id: 0,
            vector_transfer_id,
        };
        self.transfers.push(transfer)
    }

    pub fn remove_transfer(&mut self, vector_transfer_id: &Bytes32) {
        if let Some(index) = self
            .transfers
            .iter()
            .position(|a| &a.vector_transfer_id == vector_transfer_id)
        {
            self.transfers.swap_remove(index);
        }
    }

    pub fn has_collateral_for(&self, locked_payment: U256) -> bool {
        self.transfers
            .iter()
            .any(|a| a.collateral >= locked_payment)
    }

    // Uses the transfer with the least collateral that can sustain the payment.
    // This is to ensure low-latency rollover between transfers, and keeping number
    // of transfers installed at any given time to a minimum. To understand, consider
    // what would happen if we selected the transfer with the highest collateral -
    // transfers would run out of collateral at the same time.
    // Random transfer selection is not much better than the worst case.
    fn select_transfer(&mut self, locked_payment: U256) -> Option<&mut Transfer> {
        let mut selected_transfer = None;
        for transfer in self.transfers.iter_mut() {
            if transfer.collateral < locked_payment {
                continue;
            }

            match selected_transfer {
                None => selected_transfer = Some(transfer),
                Some(ref mut selected) => {
                    if selected.collateral > transfer.collateral {
                        *selected = transfer;
                    }
                }
            }
        }
        selected_transfer
    }

    fn transfer_by_id_mut(&mut self, vector_transfer_id: &Bytes32) -> Option<&mut Transfer> {
        self.transfers
            .iter_mut()
            .find(|a| &a.vector_transfer_id == vector_transfer_id)
    }

    pub fn commit(&mut self, locked_payment: U256) -> Result<Vec<u8>, BorrowFail> {
        let transfer = self
            .select_transfer(locked_payment)
            .ok_or(BorrowFail::InsufficientCollateral)?;
        transfer.collateral -= locked_payment;

        let receipt = if transfer.receipt_cache.len() == 0 {
            // This starts with the id of 1 because the transfer definition contract
            // was written in a way that makes the receipt id of 0 invalid.
            //
            // Technically running out of ids is not "insufficient collateral",
            // but it kind of is if you consider the collateral
            // to be inaccessible. Also the mitigation is the same -
            // rotating apps.
            let receipt_id = transfer
                .prev_receipt_id
                .checked_add(1)
                .ok_or(BorrowFail::InsufficientCollateral)?;
            transfer.prev_receipt_id = receipt_id;
            PooledReceipt {
                receipt_id,
                unlocked_payment: U256::zero(),
            }
        } else {
            let receipts = &mut transfer.receipt_cache;
            let index = rng().gen_range(0..receipts.len());
            receipts.swap_remove(index)
        };

        // Write the data in the official receipt that gets sent over the wire.
        // This is: [vector_transfer_id, payment_amount, receipt_id, signature]
        // That this math cannot overflow otherwise the transfer would have run out of collateral.
        let mut dest = Vec::with_capacity(BORROWED_RECEIPT_LEN);
        let payment_amount = receipt.unlocked_payment + locked_payment;
        dest.extend_from_slice(&transfer.vector_transfer_id);
        dest.extend_from_slice(&to_le_bytes(payment_amount));
        dest.extend_from_slice(&receipt.receipt_id.to_le_bytes());

        // Engineering in any kind of replay protection like as afforded by EIP-712 is
        // unnecessary, because the signer key needs to be unique per app. It is a straightforward
        // extension from there to also say that the signer key should be globally unique and
        // not sign any messages that are not for the app. Since there are no other structs
        // to sign, there are no possible collisions.
        //
        // The part of the message that needs to be signed in the payment amount and receipt id only.
        let signed_data = &dest[PAYMENT_AMOUNT_RANGE.start..RECEIPT_ID_RANGE.end];
        let message = Message::from_slice(&hash_bytes(signed_data)).unwrap();
        let signature = SIGNER.sign_recoverable(&message, &transfer.signer);
        let (recovery_id, signature) = signature.serialize_compact();
        let recovery_id = match recovery_id.to_i32() {
            0 => 27,
            1 => 28,
            27 => 27,
            28 => 28,
            _ => panic!("Invalid recovery id"),
        };
        dest.extend_from_slice(&signature);
        dest.push(recovery_id);

        // Extend with the unlocked payment, which is necessary to return collateral
        // in the case of failure.
        dest.extend_from_slice(&to_le_bytes(receipt.unlocked_payment));

        debug_assert_eq!(BORROWED_RECEIPT_LEN, dest.len());

        Ok(dest)
    }

    pub fn release(&mut self, bytes: &[u8], status: QueryStatus) {
        assert_eq!(bytes.len(), BORROWED_RECEIPT_LEN);
        let vector_transfer_id: Bytes32 = bytes[VECTOR_TRANSFER_ID_RANGE].try_into().unwrap();

        // Try to find the transfer. If there is no transfer, it means it's been uninstalled.
        // In that case, drop the receipt.
        let transfer = if let Some(transfer) = self.transfer_by_id_mut(&vector_transfer_id) {
            transfer
        } else {
            return;
        };

        let payment_amount = U256::from_little_endian(&bytes[PAYMENT_AMOUNT_RANGE]);
        let unlocked_payment = U256::from_little_endian(&bytes[UNLOCKED_PAYMENT_RANGE]);
        let locked_payment = payment_amount - unlocked_payment;

        let mut receipt = PooledReceipt {
            unlocked_payment,
            receipt_id: ReceiptID::from_le_bytes(bytes[RECEIPT_ID_RANGE].try_into().unwrap()),
        };

        let funds_destination = match status {
            QueryStatus::Failure => &mut transfer.collateral,
            QueryStatus::Success => &mut receipt.unlocked_payment,
            // If we don't know what happened (eg: timeout) we don't
            // know what the Indexer percieves the state of the receipt to
            // be. Rather than arguing about it (eg: sync protocol) just
            // never use this receipt again by dropping it here. This
            // does not change any security invariants. We also do not reclaim
            // the collateral until transfer uninstall.
            QueryStatus::Unknown => return,
        };

        *funds_destination += locked_payment;
        transfer.receipt_cache.push(receipt);
    }
}

fn to_le_bytes(value: U256) -> Bytes32 {
    let mut result = Bytes32::default();
    value.to_little_endian(&mut result);
    result
}

fn hash_bytes(bytes: &[u8]) -> Bytes32 {
    use tiny_keccak::Hasher;
    let mut hasher = tiny_keccak::Sha3::v256();
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
        assert_eq!(receipt, Err(BorrowFail::InsufficientCollateral));
    }

    #[track_caller]
    fn assert_collateral_equals(pool: &ReceiptPool, expect: impl Into<U256>) {
        let expect = expect.into();
        let mut collateral = U256::zero();
        for transfer in pool.transfers.iter() {
            collateral += transfer.collateral;
        }
        assert_eq!(expect, collateral);
    }

    #[track_caller]
    fn assert_successful_borrow(pool: &mut ReceiptPool, amount: impl Into<U256>) -> Vec<u8> {
        pool.commit(U256::from(amount.into()))
            .expect("Should have sufficient collateral")
    }

    // Has 2 transfers which if together could pay for a receipt, but separately cannot.
    //
    // It occurs to me that the updated receipts could be an array - allow this to succeed by committing
    // to partial payments across multiple transferss. This is likely not worth the complexity, but could be
    // a way to drain all transfers down to 0 remaining collateral. If this gets added and this test fails,
    // then the transfer selection test will no longer be effective. See also 460f4588-66f3-4aa3-9715-f2da8cac20b7
    #[test]
    pub fn cannot_share_collateral_across_transfers() {
        let mut pool = ReceiptPool::new();

        pool.add_transfer(test_signer(), 50.into(), bytes32(1));
        pool.add_transfer(test_signer(), 25.into(), bytes32(2));

        assert_failed_borrow(&mut pool, 60);
    }

    // Simple happy-path case of paying for requests in a loop.
    #[test]
    pub fn can_pay_for_requests() {
        let mut pool = ReceiptPool::new();
        pool.add_transfer(test_signer(), 60.into(), bytes32(1));

        for i in 1..=10 {
            let borrow = assert_successful_borrow(&mut pool, i);
            pool.release(&borrow, QueryStatus::Success);
            // Verify that we have unlocked all the payments
            let unlocked: u32 = (0..=i).sum();
            assert_eq!(U256::from(unlocked), pool.known_unlocked_payments());
        }

        // Should run out of collateral here.
        assert_failed_borrow(&mut pool, 6);
    }

    // If the transfers aren't selected optimally, then this will fail to pay for the full set.
    #[test]
    pub fn selects_best_transfers() {
        // Assumes fee cannot be split across transfers.
        // See also 460f4588-66f3-4aa3-9715-f2da8cac20b7
        let mut pool = ReceiptPool::new();

        pool.add_transfer(test_signer(), 4.into(), bytes32(1));
        pool.add_transfer(test_signer(), 3.into(), bytes32(2));
        pool.add_transfer(test_signer(), 1.into(), bytes32(3));
        pool.add_transfer(test_signer(), 2.into(), bytes32(4));
        pool.add_transfer(test_signer(), 2.into(), bytes32(5));
        pool.add_transfer(test_signer(), 1.into(), bytes32(6));
        pool.add_transfer(test_signer(), 3.into(), bytes32(7));
        pool.add_transfer(test_signer(), 4.into(), bytes32(8));

        assert_successful_borrow(&mut pool, 2);
        assert_successful_borrow(&mut pool, 4);
        assert_successful_borrow(&mut pool, 3);
        assert_successful_borrow(&mut pool, 1);
        assert_successful_borrow(&mut pool, 2);
        assert_successful_borrow(&mut pool, 3);
        assert_successful_borrow(&mut pool, 1);
        assert_successful_borrow(&mut pool, 4);

        assert_failed_borrow(&mut pool, 1);
    }

    // Any uninstalled transfer cannot be used to pay for queries.
    #[test]
    fn removed_transfer_cannot_pay() {
        let mut pool = ReceiptPool::new();
        pool.add_transfer(test_signer(), 10.into(), bytes32(2));
        pool.add_transfer(test_signer(), 3.into(), bytes32(1));

        pool.remove_transfer(&bytes32(2));

        assert_failed_borrow(&mut pool, 5);
    }

    // Tests modes for returning collateral
    #[test]
    fn collateral_return() {
        let mut pool = ReceiptPool::new();

        pool.add_transfer(test_signer(), 10.into(), bytes32(2));

        let borrow3 = assert_successful_borrow(&mut pool, 3);
        assert_collateral_equals(&pool, 7);

        let borrow2 = assert_successful_borrow(&mut pool, 2);
        assert_collateral_equals(&pool, 5);

        pool.release(&borrow3, QueryStatus::Failure);
        assert_collateral_equals(&pool, 8);

        let borrow4 = assert_successful_borrow(&mut pool, 4);
        assert_collateral_equals(&pool, 4);

        pool.release(&borrow2, QueryStatus::Success);
        assert_collateral_equals(&pool, 4);

        pool.release(&borrow4, QueryStatus::Unknown);
        assert_collateral_equals(&pool, 4);
    }
}
