//! This module provides the following cryptographic schemes:
//! - [blake2b]: The blake2b hash function
//! - [chacha20poly1305]: The Chacha20Poly1305 AEAD
//! - [incorrect_hmac_blake2b]: An (incorrect) hmac based on [blake2b].
//! - [xchacha20poly1305] The Chacha20Poly1305 AEAD as implemented in [RustCrypto](https://crates.io/crates/chacha20poly1305)

pub mod blake2b;
pub mod chacha20poly1305;
pub mod incorrect_hmac_blake2b;
pub mod xchacha20poly1305;
