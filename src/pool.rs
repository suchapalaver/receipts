use crate::prelude::*;
use eip_712_derive::DomainSeparator;
use lazy_static::lazy_static;
use secp256k1::{Message, Secp256k1, SecretKey, SignOnly};

lazy_static! {
    static ref SIGNER: Secp256k1<SignOnly> = Secp256k1::signing_only();
}
pub const BORROWED_RECEIPT_LEN: usize = 152;

/// A collection of installed app that can borrow or generate receipts.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct ReceiptPool {
    apps: Vec<App>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Keys {
    pub address: Address,
    pub secret: SecretKey,
    pub domain: DomainSeparator,
}

/// A in-flight app state for a payment app that has been installed on Vector.
// This must never implement Clone
#[derive(Debug, PartialEq, Eq)]
struct App {
    /// There is no need to sync the collateral to the db. If we crash, should
    /// either rotate out apps or recover the app state from the Indexer.
    collateral: U256,
    /// The ZKP is most efficient when using receipts from a contiguous range
    /// as this allows the receipts to be constants rather than witnessed-in,
    /// and also have preset data sizes for amortized proving time.
    next_receipt_id: ReceiptID,
    /// Receipts that can be folded. These contain an unbroken chain
    /// of agreed upon history between the Indexer and Gateway.
    receipt_cache: Vec<PooledReceipt>,
    /// Keys: Signs the receipts. Each app must have a globally unique key address.
    /// If keys are shared across multiple Apps it will allow the Indexer to
    /// double-collect the same receipt across multiple apps
    keys: Keys,
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
    // If this error is encountered it means that a new app with
    // more collateral must be installed.
    InsufficientCollateral,
}

impl ReceiptPool {
    pub fn new() -> Self {
        Self { apps: Vec::new() }
    }

    /// This is only a minimum bound, and doesn't count
    /// outstanding/forgotten receipts which may have account for a
    /// large amount of unlocked payments
    #[cfg(test)]
    pub fn known_unlocked_payments(&self) -> U256 {
        let mut result = U256::zero();
        for payment in self
            .apps
            .iter()
            .flat_map(|a| &a.receipt_cache)
            .map(|r| r.unlocked_payment)
        {
            result += payment;
        }
        result
    }

    pub fn add_app(&mut self, keys: Keys, collateral: U256) {
        // Defensively ensure we don't already have this app.
        // Note that the collateral may not match, but that would be ok.
        for app in self.apps.iter() {
            if app.keys.address == keys.address {
                return;
            }
        }
        let app = App {
            keys,
            collateral,
            receipt_cache: Vec::new(),
            next_receipt_id: 0,
        };
        self.apps.push(app)
    }

    pub fn remove_app(&mut self, address: &Address) {
        if let Some(index) = self.apps.iter().position(|a| &a.keys.address == address) {
            self.apps.swap_remove(index);
        }
    }

    pub fn has_collateral_for(&self, locked_payment: U256) -> bool {
        self.apps.iter().any(|a| a.collateral >= locked_payment)
    }

    // Uses the app with the least collateral that can sustain the payment.
    // This is to ensure low-latency rollover between apps, and keeping number
    // of apps installed at any given time to a minimum. To understand, consider
    // what would happen if we selected the app with the highest collateral -
    // apps would run out at the same time. Random app selection is not much better than
    // the worst case.
    fn select_app(&mut self, locked_payment: U256) -> Option<&mut App> {
        let mut selected_app = None;
        for app in self.apps.iter_mut() {
            if app.collateral < locked_payment {
                continue;
            }

            match selected_app {
                None => selected_app = Some(app),
                Some(ref mut selected) => {
                    if selected.collateral > app.collateral {
                        *selected = app;
                    }
                }
            }
        }
        selected_app
    }

    fn app_by_id_mut(&mut self, address: &Address) -> Option<&mut App> {
        self.apps.iter_mut().find(|a| &a.keys.address == address)
    }

    pub fn commit(&mut self, locked_payment: U256) -> Result<Vec<u8>, BorrowFail> {
        let app = self
            .select_app(locked_payment)
            .ok_or(BorrowFail::InsufficientCollateral)?;
        app.collateral -= locked_payment;

        let receipt = if app.receipt_cache.len() == 0 {
            let receipt_id = app.next_receipt_id;
            app.next_receipt_id = app
                .next_receipt_id
                .checked_add(1)
                .ok_or(BorrowFail::InsufficientCollateral)?;
            PooledReceipt {
                receipt_id,
                unlocked_payment: U256::zero(),
            }
        } else {
            let receipts = &mut app.receipt_cache;
            let index = rng().gen_range(0..receipts.len());
            receipts.swap_remove(index)
        };

        // Write the data in the official receipt that gets sent over the wire.
        // This is: [vector_app_id, payment_amount, receipt_id, signature, unlocked_payment]
        // That this math cannot overflow otherwise the app would have run out of collateral.
        let mut dest = Vec::new();
        let payment_amount = receipt.unlocked_payment + locked_payment;
        dest.extend_from_slice(&app.keys.address);
        dest.extend_from_slice(&to_le_bytes(payment_amount));
        dest.extend_from_slice(&receipt.receipt_id.to_le_bytes());

        // This is diverging from EIP-712 for a couple of reasons. The main reason
        // is that EIP-712 unnecessarily uses extra hashes. Even in the best case
        // EIP-712 requires 2 hashes. When variable length data is involved, there
        // are even more hashes (which is not the most performant way to disambiguate,
        // which is what they are accomplishing). So, just taking the best parts
        // of EIP-712 here to prevent replay attacks by using a DomainSeparator. We
        // could use a struct definition too, but since we have only one struct that's not
        // necessary either.
        let message = Message::from_slice(&hash_bytes(app.keys.domain.as_bytes(), &dest)).unwrap();
        let signature = SIGNER.sign(&message, &app.keys.secret);
        dest.extend_from_slice(&signature.serialize_compact());

        dest.extend_from_slice(&to_le_bytes(payment_amount));

        Ok(dest)
    }

    pub fn release(&mut self, bytes: &[u8], status: QueryStatus) {
        assert_eq!(bytes.len(), BORROWED_RECEIPT_LEN);
        let address: Address = bytes[0..20].try_into().unwrap();

        // Try to find the app. If there is no app, it means it's been uninstalled.
        // In that case, drop the receipt.
        let app = if let Some(app) = self.app_by_id_mut(&address) {
            app
        } else {
            return;
        };

        let payment_amount = U256::from_little_endian(&bytes[20..52]);
        // signature: [56..120]
        let locked_payment = U256::from_little_endian(&bytes[120..152]);

        let mut receipt = PooledReceipt {
            unlocked_payment: payment_amount - locked_payment,
            receipt_id: ReceiptID::from_le_bytes(bytes[52..56].try_into().unwrap()),
        };

        let funds_destination = match status {
            QueryStatus::Failure => &mut app.collateral,
            QueryStatus::Success => &mut receipt.unlocked_payment,
            // If we don't know what happened (eg: timeout) we don't
            // know what the Indexer percieves the state of the receipt to
            // be. Rather than arguing about it (eg: sync protocol) just
            // never use this receipt again by dropping it here. This
            // does not change any security invariants. We also do not reclaim
            // the collateral until app uninstall.
            QueryStatus::Unknown => return,
        };

        *funds_destination += locked_payment;
        app.receipt_cache.push(receipt);
    }
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
        for app in pool.apps.iter() {
            collateral += app.collateral;
        }
        assert_eq!(expect, collateral);
    }

    #[track_caller]
    fn assert_successful_borrow(pool: &mut ReceiptPool, amount: impl Into<U256>) -> Vec<u8> {
        pool.commit(U256::from(amount.into()))
            .expect("Should have sufficient collateral")
    }

    // Has 2 apps which if together could pay for a receipt, but separately cannot.
    //
    // It occurs to me that the updated receipts could be an array - allow this to succeed by committing
    // to partial payments across multiple apps. This is likely not worth the complexity, but could be
    // a way to drain all apps down to 0 remaining collateral. If this gets added and this test fails,
    // then the app selection test will no longer be effective. See also 460f4588-66f3-4aa3-9715-f2da8cac20b7
    #[test]
    pub fn cannot_share_collateral_across_apps() {
        let mut pool = ReceiptPool::new();

        pool.add_app(test_keys(1), 50.into());
        pool.add_app(test_keys(2), 25.into());

        assert_failed_borrow(&mut pool, 60);
    }

    // Simple happy-path case of paying for requests in a loop.
    #[test]
    pub fn can_pay_for_requests() {
        let mut pool = ReceiptPool::new();
        pool.add_app(test_keys(1), 60.into());

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

    // If the apps aren't selected optimally, then this will fail to pay for the full set.
    #[test]
    pub fn selects_best_apps() {
        // Assumes fee cannot be split across apps.
        // See also 460f4588-66f3-4aa3-9715-f2da8cac20b7
        let mut pool = ReceiptPool::new();

        pool.add_app(test_keys(1), 4.into());
        pool.add_app(test_keys(2), 3.into());
        pool.add_app(test_keys(3), 1.into());
        pool.add_app(test_keys(4), 2.into());
        pool.add_app(test_keys(5), 2.into());
        pool.add_app(test_keys(6), 1.into());
        pool.add_app(test_keys(7), 3.into());
        pool.add_app(test_keys(8), 4.into());

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

    // Any uninstalled app cannot be used to pay for queries.
    #[test]
    fn removed_app_cannot_pay() {
        let mut pool = ReceiptPool::new();
        pool.add_app(test_keys(2), 10.into());
        pool.add_app(test_keys(1), 3.into());

        pool.remove_app(&test_keys(2).address);

        assert_failed_borrow(&mut pool, 5);
    }

    // Tests modes for returning collateral
    #[test]
    fn collateral_return() {
        let mut pool = ReceiptPool::new();

        pool.add_app(test_keys(2), 10.into());

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
