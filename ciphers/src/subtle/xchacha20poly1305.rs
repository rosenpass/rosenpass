use rosenpass_cipher_traits::{Aead, AeadError, Provider as ProviderTrait};
use rosenpass_util::typenum2const;

use chacha20poly1305::XChaCha20Poly1305 as AeadImpl;
use chacha20poly1305::{AeadCore, KeySizeUser};

use crate::Provider;

pub const KEY_LEN: usize = typenum2const! { <AeadImpl as KeySizeUser>::KeySize };
pub const TAG_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::TagSize };
pub const NONCE_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::NonceSize };

#[inline]
pub fn encrypt(
    ciphertext: &mut [u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<(), AeadError> {
    <Provider as ProviderTrait>::XChaCha20Poly1305::encrypt(ciphertext, key, nonce, ad, plaintext)
}

#[inline]
pub fn decrypt(
    plaintext: &mut [u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<(), AeadError> {
    <Provider as ProviderTrait>::XChaCha20Poly1305::decrypt(plaintext, key, nonce, ad, ciphertext)
}
