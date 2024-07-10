use static_assertions::const_assert;

pub mod subtle;

pub const KEY_LEN: usize = 32;
const_assert!(KEY_LEN == aead::KEY_LEN);
const_assert!(KEY_LEN == xaead::KEY_LEN);
const_assert!(KEY_LEN == hash_domain::KEY_LEN);

/// Authenticated encryption with associated data
pub mod aead {
    #[cfg(not(feature = "libcrux"))]
    pub use crate::subtle::chacha20poly1305_ietf::{decrypt, encrypt, KEY_LEN, NONCE_LEN, TAG_LEN};
    #[cfg(feature = "libcrux")]
    pub use crate::subtle::chacha20poly1305_ietf::{decrypt, encrypt, KEY_LEN, NONCE_LEN, TAG_LEN};
}

/// Authenticated encryption with associated data with a constant nonce
pub mod xaead {
    pub use crate::subtle::xchacha20poly1305_ietf::{
        decrypt, encrypt, KEY_LEN, NONCE_LEN, TAG_LEN,
    };
}

pub mod hash_domain;

pub mod kem {
    pub use rosenpass_oqs::ClassicMceliece460896 as StaticKem;
    pub use rosenpass_oqs::Kyber512 as EphemeralKem;
}
