pub mod aead {
    pub use rosenpass_sodium::aead::chacha20poly1305_ietf::{
        decrypt, encrypt, KEY_LEN, NONCE_LEN, TAG_LEN,
    };
}
