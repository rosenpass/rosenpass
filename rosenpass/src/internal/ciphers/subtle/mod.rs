//! # Rosenpass internal cryptographic primitives
//! 
//! Ciphers and other cryptographic primitives used by rosenpass.
//! 
//! This is an internal library; not guarantee is made about its API at this point in time.


pub mod keyed_hash;

pub use custom::incorrect_hmac_blake2b;
pub use rust_crypto::{blake2b, keyed_shake256};

pub mod custom;
pub mod rust_crypto;
