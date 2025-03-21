//! This module provides types that enabling choosing the keyed hash building block to be used at
//! runtime (using enums) instead of at compile time (using generics).

use std::fmt::Display;
use anyhow::Result;
use rosenpass_cipher_traits::primitives::KeyedHashInstance;

use crate::subtle::{
    custom::incorrect_hmac_blake2b::IncorrectHmacBlake2b, rust_crypto::keyed_shake256::SHAKE256_32,
};

/// Length of symmetric key throughout Rosenpass.
pub const KEY_LEN: usize = 32;

/// The hash is used as a symmetric key and should have the same length.
pub const HASH_LEN: usize = KEY_LEN;

/// Provides a way to pick which keyed hash to use at runtime.
/// Implements [`KeyedHashInstance`] to allow hashing using the respective algorithm.
#[derive(Debug, Eq, PartialEq, Clone)]
pub enum KeyedHash {
    /// A hasher backed by [`SHAKE256_32`].
    KeyedShake256(SHAKE256_32),
    /// A hasher backed by [`IncorrectHmacBlake2b`].
    IncorrectHmacBlake2b(IncorrectHmacBlake2b),
}

impl KeyedHash {
    /// Creates an [`KeyedHash`] backed by SHAKE256.
    pub fn keyed_shake256() -> Self {
        Self::KeyedShake256(Default::default())
    }

    /// Creates an [`KeyedHash`] backed by Blake2B.
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
            Self::KeyedShake256(h) => h.keyed_hash(key, data, out)?,
            Self::IncorrectHmacBlake2b(h) => h.keyed_hash(key, data, out)?,
        };

        Ok(())
    }
}

impl Display for KeyedHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::KeyedShake256(_) => write!(f, "KeyedShake256_32"),
            Self::IncorrectHmacBlake2b(_) => write!(f, "IncorrectHmacBlake2b"),
        }
    }
    
}
