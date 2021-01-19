use crate::prelude::*;

/// A collection of installed app that can borrow or generate receipts.
#[derive(Default, Debug, PartialEq, Eq)]
pub struct ReceiptPool {
    apps: Vec<App>,
}

/// A in-flight app state for a payment app that has been installed on Vector.
// This must never implement Clone
#[derive(Debug, PartialEq, Eq)]
struct App {
    /// The app id in Vector. All receipts must be signed with this id to prevent
    /// a receipt being collected across multiple apps.
    vector_id: Bytes32,
    /// There is no need to sync the collateral to the db. If we crash, should
    /// either rotate out apps or recover the app state from the Indexer.
    collateral: U256,
    /// Receipts that can be folded. These contain an unbroken chain
    /// of agreed upon history between the Indexer and Gateway.
    receipt_cache: Vec<PooledReceipt>,
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

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct BorrowedReceipt {
    pub(crate) vector_app_id: Bytes32,
    pub(crate) locked_payment: U256,
    pub(crate) pooled_receipt: PooledReceipt,
}

impl BorrowedReceipt {
    pub fn locked_payment(&self) -> U256 {
        self.locked_payment
    }
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
    pub fn add_app(&mut self, vector_id: Bytes32, collateral: U256) {
        // Defensively ensure we don't already have this app.
        // Note that the collateral may not match, but that would be ok.
        for app in self.apps.iter() {
            if app.vector_id == vector_id {
                return;
            }
        }
        let app = App {
            vector_id,
            collateral,
            receipt_cache: Vec::new(),
        };
        self.apps.push(app)
    }
    pub fn remove_app(&mut self, vector_id: &Bytes32) {
        if let Some(index) = self.apps.iter().position(|a| &a.vector_id == vector_id) {
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

    fn app_by_id_mut(&mut self, vector_id: &Bytes32) -> Option<&mut App> {
        self.apps.iter_mut().find(|a| &a.vector_id == vector_id)
    }

    pub fn borrow(&mut self, locked_payment: U256) -> Result<BorrowedReceipt, BorrowFail> {
        let app = self
            .select_app(locked_payment)
            .ok_or(BorrowFail::InsufficientCollateral)?;
        app.collateral -= locked_payment;

        let pooled_receipt = if app.receipt_cache.len() == 0 {
            let mut receipt_id = Bytes16::default();
            rng().fill_bytes(&mut receipt_id);
            PooledReceipt {
                receipt_id,
                unlocked_payment: U256::zero(),
            }
        } else {
            let receipts = &mut app.receipt_cache;
            let index = rng().gen_range(0..receipts.len());
            receipts.swap_remove(index)
        };

        Ok(BorrowedReceipt {
            vector_app_id: app.vector_id,
            locked_payment,
            pooled_receipt,
        })
    }

    pub fn release(&mut self, mut borrowed: BorrowedReceipt, status: QueryStatus) {
        // Try to find the app. If there is no app, it means it's been uninstalled.
        // In that case, drop the receipt.
        let app = if let Some(app) = self.app_by_id_mut(&borrowed.vector_app_id) {
            app
        } else {
            return;
        };

        let funds_destination = match status {
            QueryStatus::Failure => &mut app.collateral,
            QueryStatus::Success => &mut borrowed.pooled_receipt.unlocked_payment,
            // If we don't know what happened (eg: timeout) we don't
            // know what the Indexer percieves the state of the receipt to
            // be. Rather than arguing about it (eg: sync protocol) just
            // never use this receipt again by dropping it here. This
            // does not change any security invariants. We also do not reclaim
            // the collateral until app uninstall.
            QueryStatus::Unknown => return,
        };

        *funds_destination += borrowed.locked_payment;
        app.receipt_cache.push(borrowed.pooled_receipt);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[track_caller]
    fn assert_failed_borrow(pool: &mut ReceiptPool, amount: impl Into<U256>) {
        let receipt = pool.borrow(amount.into());
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
    fn assert_successful_borrow(
        pool: &mut ReceiptPool,
        amount: impl Into<U256>,
    ) -> BorrowedReceipt {
        pool.borrow(U256::from(amount.into()))
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

        pool.add_app(bytes32(1), 50.into());
        pool.add_app(bytes32(2), 25.into());

        assert_failed_borrow(&mut pool, 60);
    }

    // Simple happy-path case of paying for requests in a loop.
    #[test]
    pub fn can_pay_for_requests() {
        let mut pool = ReceiptPool::new();
        pool.add_app(bytes32(1), 60.into());

        for i in 1..=10 {
            let borrow = assert_successful_borrow(&mut pool, i);
            // Verify that we have unlocked all the previous payments
            let unlocked: u32 = (0..i).sum();
            assert_eq!(U256::from(unlocked), borrow.pooled_receipt.unlocked_payment);
            pool.release(borrow, QueryStatus::Success);
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

        pool.add_app(bytes32(1), 4.into());
        pool.add_app(bytes32(2), 3.into());
        pool.add_app(bytes32(3), 1.into());
        pool.add_app(bytes32(4), 2.into());
        pool.add_app(bytes32(5), 2.into());
        pool.add_app(bytes32(6), 1.into());
        pool.add_app(bytes32(7), 3.into());
        pool.add_app(bytes32(8), 4.into());

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
        pool.add_app(bytes32(2), 10.into());
        pool.add_app(bytes32(1), 3.into());

        pool.remove_app(&bytes32(2));

        assert_failed_borrow(&mut pool, 5);
    }

    // Tests modes for returning collateral
    #[test]
    fn collateral_return() {
        let mut pool = ReceiptPool::new();

        pool.add_app(bytes32(2), 10.into());

        let borrow3 = assert_successful_borrow(&mut pool, 3);
        assert_collateral_equals(&pool, 7);

        let borrow2 = assert_successful_borrow(&mut pool, 2);
        assert_collateral_equals(&pool, 5);

        pool.release(borrow3, QueryStatus::Failure);
        assert_collateral_equals(&pool, 8);

        let borrow4 = assert_successful_borrow(&mut pool, 4);
        assert_collateral_equals(&pool, 4);

        pool.release(borrow2, QueryStatus::Success);
        assert_collateral_equals(&pool, 4);

        pool.release(borrow4, QueryStatus::Unknown);
        assert_collateral_equals(&pool, 4);
    }
}
