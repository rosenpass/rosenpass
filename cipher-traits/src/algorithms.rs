pub mod keyed_hash_blake2b {
    use crate::primitives::keyed_hash::*;

    pub const KEY_LEN: usize = 32;
    pub const OUT_LEN: usize = 32;

    pub trait KeyedHashBlake2b: KeyedHash<KEY_LEN, OUT_LEN> {}
}

pub mod aead_chacha20poly1305 {
    use crate::primitives::aead::*;

    pub const KEY_LEN: usize = 32;
    pub const NONCE_LEN: usize = 12;
    pub const TAG_LEN: usize = 16;

    pub trait AeadChaCha20Poly1305: Aead<KEY_LEN, NONCE_LEN, TAG_LEN> {}
}

pub mod aead_xchacha20poly1305 {
    use crate::primitives::aead::*;

    pub const KEY_LEN: usize = 32;
    pub const NONCE_LEN: usize = 24;
    pub const TAG_LEN: usize = 16;

    pub trait AeadXChaCha20Poly1305: Aead<KEY_LEN, NONCE_LEN, TAG_LEN> {}
}

pub mod kem_kyber512 {
    use crate::primitives::kem::*;

    // page 33 of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.203.ipd.pdf
    // (which is ml-kem instead of kyber, but it's the same)
    pub const SK_LEN: usize = 1632;
    pub const PK_LEN: usize = 800;
    pub const CT_LEN: usize = 768;
    pub const SHK_LEN: usize = 32;

    pub trait KemKyber512: Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> {}
}

pub mod kem_classic_mceliece460896 {
    use crate::primitives::kem::*;

    // page 6 of https://classic.mceliece.org/mceliece-impl-20221023.pdf
    pub const SK_LEN: usize = 13608;
    pub const PK_LEN: usize = 524160;
    pub const CT_LEN: usize = 156;
    pub const SHK_LEN: usize = 32;

    pub trait KemClassicMceliece460896: Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> {}
}

pub use aead_chacha20poly1305::AeadChaCha20Poly1305;
pub use aead_xchacha20poly1305::AeadXChaCha20Poly1305;

pub use kem_classic_mceliece460896::KemClassicMceliece460896;
pub use kem_kyber512::KemKyber512;

pub use keyed_hash_blake2b::KeyedHashBlake2b;
