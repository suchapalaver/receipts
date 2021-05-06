use receipts_transfer;

impl From<crate::BorrowFail> for receipts_transfer::BorrowFail {
    fn from(value: crate::BorrowFail) -> receipts_transfer::BorrowFail {
        // Hack
        match value {
            crate::BorrowFail::NoAllocation => {
                receipts_transfer::BorrowFail::InsufficientCollateral
            }
        }
    }
}

impl From<crate::QueryStatus> for receipts_transfer::QueryStatus {
    fn from(value: crate::QueryStatus) -> receipts_transfer::QueryStatus {
        match value {
            crate::QueryStatus::Failure => receipts_transfer::QueryStatus::Failure,
            crate::QueryStatus::Success => receipts_transfer::QueryStatus::Success,
            crate::QueryStatus::Unknown => receipts_transfer::QueryStatus::Unknown,
        }
    }
}
