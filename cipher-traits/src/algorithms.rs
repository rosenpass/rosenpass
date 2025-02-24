pub mod keyed_hash_blake2b {
    use crate::primitives::keyed_hash::*;

    pub const KEY_LEN: usize = 32;
    pub const OUT_LEN: usize = 32;

    pub trait KeyedHashBlake2b: KeyedHash<KEY_LEN, OUT_LEN> {}
}

pub mod keyed_hash_shake256 {
    use crate::primitives::keyed_hash::*;

    pub const KEY_LEN: usize = 32;
    pub const OUT_LEN: usize = 32;

    pub trait KeyedHashShake256: KeyedHash<KEY_LEN, OUT_LEN> {}
}

pub use keyed_hash_blake2b::KeyedHashBlake2b;
pub use keyed_hash_shake256::KeyedHashShake256;
