/// This module provides the following cryptographic schemes:
/// - [blake2b]: The blake2b hash function
/// - [chacha20poly1305_ietf]: The Chacha20Poly1305 AEAD as implemented in [RustCrypto](https://crates.io/crates/chacha20poly1305) (only used when the feature `experiment_libcrux` is disabled).
/// - [chacha20poly1305_ietf_libcrux]: The Chacha20Poly1305 AEAD as implemented in [libcrux](https://github.com/cryspen/libcrux) (only used when the feature `experiment_libcrux` is enabled).
/// - [incorrect_hmac_blake2b]: An (incorrect) hmac based on [blake2b].
/// - [xchacha20poly1305_ietf] The Chacha20Poly1305 AEAD as implemented in [RustCrypto](https://crates.io/crates/chacha20poly1305)
pub mod blake2b;
#[cfg(not(feature = "experiment_libcrux"))]
pub mod chacha20poly1305_ietf;
#[cfg(feature = "experiment_libcrux")]
pub mod chacha20poly1305_ietf_libcrux;
pub mod incorrect_hmac_blake2b;
pub mod xchacha20poly1305_ietf;
pub mod hash_functions;

pub use hash_functions::{keyed_shake256}; 