//! # Rosenpass internal cryptographic primitives
//!
//! Ciphers and other cryptographic primitives used by rosenpass.
//!
//! This is an internal library; no guarantee is made about its API at this point in time.

pub mod custom;
pub mod ephemeral_kem_choice;
pub mod keyed_hash;
pub mod rust_crypto;

pub use custom::incorrect_hmac_blake2b;
pub use ephemeral_kem_choice::EphemeralKemChoice;
pub use rust_crypto::{blake2b, keyed_shake256};
