pub(crate) use {
    primitive_types::U256,
    rand::{thread_rng as rng, Rng as _},
    std::convert::TryInto as _,
};

pub type Bytes32 = [u8; 32];
pub type Address = [u8; 20];
pub type Bytes16 = [u8; 16];
