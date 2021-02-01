mod pool;
mod prelude;

use eip_712_derive::{Address, DomainSeparator, Eip712Domain};
pub use pool::{BorrowFail, QueryStatus, ReceiptPool};

extern crate lazy_static;

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
