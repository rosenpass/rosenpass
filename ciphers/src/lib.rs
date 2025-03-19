use rosenpass_cipher_traits::primitives::Aead as _;
use static_assertions::const_assert;

pub mod subtle;

/// All keyed primitives in this crate use 32 byte keys
pub const KEY_LEN: usize = 32;
const_assert!(KEY_LEN == hash_domain::KEY_LEN);

/// Keyed hashing
///
/// This should only be used for implementation details; anything with relevance
/// to the cryptographic protocol should use the facilities in [hash_domain], (though
/// hash domain uses this module internally)
pub use crate::subtle::keyed_hash::KeyedHash;

/// Authenticated encryption with associated data (AEAD)
/// Chacha20poly1305 is used.
#[cfg(feature = "experiment_libcrux_chachapoly")]
pub use subtle::libcrux::chacha20poly1305_ietf::ChaCha20Poly1305 as Aead;

/// Authenticated encryption with associated data (AEAD)
/// Chacha20poly1305 is used.
#[cfg(not(feature = "experiment_libcrux_chachapoly"))]
pub use crate::subtle::rust_crypto::chacha20poly1305_ietf::ChaCha20Poly1305 as Aead;

/// Authenticated encryption with associated data with a extended-length nonce (XAEAD)
/// XChacha20poly1305 is used.
pub use crate::subtle::rust_crypto::xchacha20poly1305_ietf::XChaCha20Poly1305 as XAead;

/// Use Classic-McEcliece-460986 as the Static KEM.
///
/// See [rosenpass_oqs::ClassicMceliece460896] for more details.
pub use rosenpass_oqs::ClassicMceliece460896 as StaticKem;

/// Use Kyber-512 as the Static KEM
///
/// See [rosenpass_oqs::Kyber512] for more details.
#[cfg(not(feature = "experiment_libcrux_kyber"))]
pub use rosenpass_oqs::Kyber512 as EphemeralKem;
#[cfg(feature = "experiment_libcrux_kyber")]
pub use subtle::libcrux::kyber512::Kyber512 as EphemeralKem;

pub mod hash_domain;
