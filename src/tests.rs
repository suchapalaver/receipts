use crate::*;
use eip_712_derive::chain_id::GETH_PRIVATE_DEFAULT;
use std::time::Instant;

pub fn bytes32<T: Into<U256>>(value: T) -> Bytes32 {
    let value = value.into();
    let mut result = Bytes32::default();
    value.to_little_endian(&mut result);
    result
}

pub fn test_sign_data() -> (SecretKey, DomainSeparator) {
    let secret_key: SecretKey = "244226452948404D635166546A576E5A7234753778217A25432A462D4A614E64"
        .parse()
        .unwrap();
    let domain_separator =
        crate::domain_separator(GETH_PRIVATE_DEFAULT, Address(Default::default()));
    (secret_key, domain_separator)
}

#[test]
#[ignore = "This panics to output the result time. Should use a proper benchmarking lib."]
fn speed() {
    let mut pool = ReceiptPool::new();
    pool.add_app(bytes32(1), U256::from(10000));
    pool.add_app(bytes32(2), U256::from(1000000000));

    let mut borrows = Vec::<Vec<u8>>::new();
    let (secret_key, domain_separator) = test_sign_data();

    let start = Instant::now();

    for _ in 0..2300 {
        for _ in 0..10 {
            let mut commitment = Vec::with_capacity(176);
            borrow_payment_commitment(
                &mut pool,
                U256::from(100),
                &secret_key,
                &domain_separator,
                &mut commitment,
            )
            .unwrap();
            assert_eq!(commitment.len(), 176);
            borrows.push(commitment)
        }
        while let Some(borrow) = borrows.pop() {
            release_payment(&borrow, &mut pool, QueryStatus::Success);
        }
    }

    let end = Instant::now();

    panic!("{:?}", end - start);
}
