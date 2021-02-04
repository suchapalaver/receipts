pub(crate) use {
    primitive_types::U256,
    rand::{thread_rng as rng, Rng as _},
    std::convert::TryInto as _,
};

pub type Bytes32 = [u8; 32];

// u32 is chosen because it is unlikely that the ZKP will be able to
// scale past this many constraints any time soon. This is enough
// to drop 1 receipt without re-use every millisecond for 49 days straight.
// Without protection, that would be grounds for worry but in the event this
// does overflow, just claim insufficient collateral and rotate the payment app.
pub type ReceiptID = u32;
