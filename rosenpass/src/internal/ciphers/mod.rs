use crate::internal::cipher_traits::primitives::Aead as AeadTrait;
use static_assertions::const_assert;

pub mod hash_domain;
pub mod subtle;

pub use subtle::ephemeral_kem_choice::EphemeralKemChoice;

// ==================== cipher choices ====================

/// All keyed primitives in this module use 32 byte keys
pub const KEY_LEN: usize = 32;
const_assert!(KEY_LEN == Aead::KEY_LEN);
const_assert!(KEY_LEN == XAead::KEY_LEN);
const_assert!(KEY_LEN == hash_domain::KEY_LEN);

/// Use Shake256 or Blake2b for keyed hashing
///
/// The choice of hashing function depends on the protocol version
/// (choice during runtime).
///
/// This should only be used for implementation details; anything with relevance
/// to the cryptographic protocol should use the facilities in [hash_domain], (though
/// hash domain uses this module internally)
pub use subtle::keyed_hash::KeyedHash;

/// Authenticated encryption with associated data (AEAD)
/// Chacha20poly1305 is used.
pub use subtle::rust_crypto::chacha20poly1305_ietf::ChaCha20Poly1305 as Aead;

/// Authenticated encryption with associated data with a extended-length nonce (XAEAD)
/// XChacha20poly1305 is used.
pub use subtle::rust_crypto::xchacha20poly1305_ietf::XChaCha20Poly1305 as XAead;

/// Use Classic-McEcliece-460986 as the Static KEM.
///
/// See [crate::internal::oqs::ClassicMceliece460896] for more details.
pub use crate::internal::oqs::ClassicMceliece460896 as StaticKem;

/// Use Kyber-512 or ML-KEM as the Static KEM
///
/// The user can choose which one of these two KEMs will be used
/// (choice during run time).
///
/// see type variants documentation for more details
pub use subtle::ephemeral_kem_choice::EphemeralKemChoice as EphemeralKem;
