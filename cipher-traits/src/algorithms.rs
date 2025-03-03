//! This module contains the traits for all the cryptographic algorithms used throughout Rosenpass.
//! These traits are marker traits that signal intent. They can also be used for trait objects.

/// Constants and trait for the Incorrect HMAC over Blake2b, with 256 key and hash length.
pub mod keyed_hash_incorrect_hmac_blake2b {
    use crate::primitives::keyed_hash::*;

    // These constants describe how they are used here, not what the algorithm defines.

    /// The key length used in [`KeyedHashIncorrectHmacBlake2b`].
    pub const KEY_LEN: usize = 32;
    /// The hash length used in [`KeyedHashIncorrectHmacBlake2b`].
    pub const HASH_LEN: usize = 32;

    /// A [`KeyedHash`] that is an incorrect HMAC over Blake2 (a custom Rosenpass construction)
    pub trait KeyedHashIncorrectHmacBlake2b: KeyedHash<KEY_LEN, HASH_LEN> {}
}

/// Constants and trait for Blake2b, with 256 key and hash length.
pub mod keyed_hash_blake2b {
    use crate::primitives::keyed_hash::*;

    // These constants describe how they are used here, not what the algorithm defines.

    /// The key length used in [`KeyedHashBlake2b`].
    pub const KEY_LEN: usize = 32;
    /// The hash length used in [`KeyedHashBlake2b`].
    pub const HASH_LEN: usize = 32;

    /// A [`KeyedHash`] that is Blake2b
    pub trait KeyedHashBlake2b: KeyedHash<KEY_LEN, HASH_LEN> {}
}

/// Constants and trait for SHAKE256, with 256 key and hash length.
pub mod keyed_hash_shake256 {
    use crate::primitives::keyed_hash::*;

    // These constants describe how they are used here, not what the algorithm defines.

    /// The key length used in [`KeyedHashShake256`].
    pub const KEY_LEN: usize = 32;
    /// The hash length used in [`KeyedHashShake256`].
    pub const HASH_LEN: usize = 32;

    /// A [`KeyedHash`] that is SHAKE256.
    pub trait KeyedHashShake256: KeyedHash<KEY_LEN, HASH_LEN> {}
}

/// Constants and trait for the ChaCha20Poly1305 AEAD
pub mod aead_chacha20poly1305 {
    use crate::primitives::aead::*;

    // See https://datatracker.ietf.org/doc/html/rfc7539#section-2.8

    /// The key length used in [`AeadChaCha20Poly1305`].
    pub const KEY_LEN: usize = 32;
    /// The nonce length used in [`AeadChaCha20Poly1305`].
    pub const NONCE_LEN: usize = 12;
    /// The tag length used in [`AeadChaCha20Poly1305`].
    pub const TAG_LEN: usize = 16;

    /// An [`Aead`] that is ChaCha20Poly1305.
    pub trait AeadChaCha20Poly1305: Aead<KEY_LEN, NONCE_LEN, TAG_LEN> {}
}

/// Constants and trait for the XChaCha20Poly1305 AEAD (i.e. ChaCha20Poly1305 with extended nonce
/// lengths)
pub mod aead_xchacha20poly1305 {
    use crate::primitives::aead::*;

    // See https://datatracker.ietf.org/doc/html/draft-irtf-cfrg-xchacha-03

    /// The key length used in [`AeadXChaCha20Poly1305`].
    pub const KEY_LEN: usize = 32;
    /// The nonce length used in [`AeadXChaCha20Poly1305`].
    pub const NONCE_LEN: usize = 24;
    /// The tag length used in [`AeadXChaCha20Poly1305`].
    pub const TAG_LEN: usize = 16;

    /// An [`Aead`] that is XChaCha20Poly1305.
    pub trait AeadXChaCha20Poly1305: Aead<KEY_LEN, NONCE_LEN, TAG_LEN> {}
}

/// Constants and trait for the Kyber512 KEM
pub mod kem_kyber512 {
    use crate::primitives::kem::*;

    // page 39 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.pdf
    // (which is ml-kem instead of kyber, but it's the same)

    /// The secret key length used in [`KemKyber512`].
    pub const SK_LEN: usize = 1632;

    /// The public key length used in [`KemKyber512`].
    pub const PK_LEN: usize = 800;

    /// The ciphertext length used in [`KemKyber512`].
    pub const CT_LEN: usize = 768;

    /// The shared key length used in [`KemKyber512`].
    pub const SHK_LEN: usize = 32;

    /// A [`Kem`] that is Kyber512.
    pub trait KemKyber512: Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> {}
}

/// Constants and trait for the Classic McEliece 460896 KEM
pub mod kem_classic_mceliece460896 {
    use crate::primitives::kem::*;

    // page 6 of https://classic.mceliece.org/mceliece-impl-20221023.pdf

    /// The secret key length used in [`KemClassicMceliece460896`].
    pub const SK_LEN: usize = 13608;

    /// The public key length used in [`KemClassicMceliece460896`].
    pub const PK_LEN: usize = 524160;

    /// The ciphertext length used in [`KemClassicMceliece460896`].
    pub const CT_LEN: usize = 156;

    /// The shared key length used in [`KemClassicMceliece460896`].
    pub const SHK_LEN: usize = 32;

    /// A [`Kem`] that is ClassicMceliece460896.
    pub trait KemClassicMceliece460896: Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> {}
}

pub use aead_chacha20poly1305::AeadChaCha20Poly1305;
pub use aead_xchacha20poly1305::AeadXChaCha20Poly1305;

pub use kem_classic_mceliece460896::KemClassicMceliece460896;
pub use kem_kyber512::KemKyber512;

pub use keyed_hash_blake2b::KeyedHashBlake2b;
pub use keyed_hash_incorrect_hmac_blake2b::KeyedHashIncorrectHmacBlake2b;
pub use keyed_hash_shake256::KeyedHashShake256;
