use anyhow::Result;
use rosenpass_cipher_traits::primitives::KeyedHashInstance;

pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;

#[derive(Debug, Eq, PartialEq, Clone)]
pub enum KeyedHash {
    KeyedShake256(super::rust_crypto::keyed_shake256::SHAKE256<KEY_LEN, HASH_LEN>),
    IncorrectHmacBlake2b(super::custom::incorrect_hmac_blake2b::IncorrectHmacBlake2b),
}

impl KeyedHash {
    pub fn keyed_shake256() -> Self {
        Self::KeyedShake256(Default::default())
    }

    pub fn incorrect_hmac_blake2b() -> Self {
        Self::IncorrectHmacBlake2b(Default::default())
    }
}

impl KeyedHashInstance<KEY_LEN, HASH_LEN> for KeyedHash {
    type Error = anyhow::Error;

    fn keyed_hash(
        &self,
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        match self {
            Self::KeyedShake256(h) => h.keyed_hash(key, data, out),
            Self::IncorrectHmacBlake2b(h) => h.keyed_hash(key, data, out),
        }
    }
}
