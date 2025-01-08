use static_assertions::const_assert;

pub mod hash_domain;
pub mod providers;
pub mod subtle;

/// All keyed primitives in this crate use 32 byte keys
pub const KEY_LEN: usize = 32;
const_assert!(KEY_LEN == aead::KEY_LEN);
const_assert!(KEY_LEN == xaead::KEY_LEN);
const_assert!(KEY_LEN == hash_domain::KEY_LEN);

/// Keyed hashing
///
/// This should only be used for implementation details; anything with relevance
/// to the cryptographic protocol should use the facilities in [hash_domain], (though
/// hash domain uses this module internally)
pub mod keyed_hash {
    pub use crate::subtle::incorrect_hmac_blake2b::{hash, KEY_LEN};
}

/// Authenticated encryption with associated data
/// Chacha20poly1305 is used.
pub mod aead {
    pub use crate::subtle::chacha20poly1305::{decrypt, encrypt, KEY_LEN, NONCE_LEN, TAG_LEN};
}

/// Authenticated encryption with associated data with a constant nonce
/// XChacha20poly1305 is used.
pub mod xaead {
    pub use crate::subtle::xchacha20poly1305::{decrypt, encrypt, KEY_LEN, NONCE_LEN, TAG_LEN};
}

/// This crate includes two key encapsulation mechanisms.
/// Namely ClassicMceliece460896 (also referred to as `StaticKem` sometimes) and
/// Kyber512 (also referred to as  `EphemeralKem` sometimes).
///
/// See [rosenpass_oqs::ClassicMceliece460896]
/// and [rosenpass_oqs::Kyber512] for more details on the specific KEMS.
///
pub mod kem {
    pub type StaticKem =
        <crate::Provider as rosenpass_cipher_traits::Provider>::ClassicMceliece460896;
    pub type EphemeralKem = <crate::Provider as rosenpass_cipher_traits::Provider>::Kyber512;
}

#[cfg(not(feature = "experiment_libcrux"))]
pub type Provider = providers::basic::BasicProvider;
#[cfg(feature = "experiment_libcrux")]
pub type Provider = providers::libcrux::LibcruxProvider;
