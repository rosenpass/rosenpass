//! Traits for cryptographic primitives used in Rosenpass, specifically KEM, AEAD and keyed
//! hashing.

pub(crate) mod aead;
pub(crate) mod kem;
pub(crate) mod keyed_hash;

pub use aead::{Aead, AeadWithNonceInCiphertext, Error as AeadError};
pub use kem::{Error as KemError, Kem};
pub use keyed_hash::*;
