use libsodium_sys as libsodium;
use std::ffi::c_ulonglong;
use std::ptr::{null, null_mut};
use thiserror::Error;

// Define a custom error type using thiserror
#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption error: {0}")]
    EncryptError(#[from] libsodium::sodium::SodiumError),

    #[error("Decryption error: {0}")]
    DecryptError(#[from] libsodium::sodium::SodiumError),
}

pub const KEY_LEN: usize = libsodium::crypto_aead_chacha20poly1305_IETF_KEYBYTES as usize;
pub const TAG_LEN: usize = libsodium::crypto_aead_chacha20poly1305_IETF_ABYTES as usize;
pub const NONCE_LEN: usize = libsodium::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize;

#[inline]
pub fn encrypt(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<(), CryptoError> {
    assert!(ciphertext.len() == plaintext.len() + TAG_LEN);
    assert!(key.len() == KEY_LEN);
    assert!(nonce.len() == NONCE_LEN);

    let mut clen: u64 = 0;
    if let Err(err) = sodium_call!(
        crypto_aead_chacha20poly1305_ietf_encrypt,
        ciphertext.as_mut_ptr(),
        &mut clen,
        plaintext.as_ptr(),
        plaintext.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        null(),// nsec is not used
        nonce.as_ptr(),
        key.as_ptr()
    ) {
        log::error!("Encryption failed: {}", err);
        return Err(CryptoError::EncryptError(err.into()));
    }

    assert!(clen as usize == ciphertext.len());
    Ok(())
}

#[inline]
pub fn decrypt(
    plaintext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<(), CryptoError> {
    assert!(ciphertext.len() == plaintext.len() + TAG_LEN);
    assert!(key.len() == KEY_LEN);
    assert!(nonce.len() == NONCE_LEN);

    let mut mlen: u64 = 0;
    if let Err(err) = sodium_call!(
        crypto_aead_chacha20poly1305_ietf_decrypt,
        plaintext.as_mut_ptr(),
        &mut mlen as *mut c_ulonglong,
        null_mut(),// nsec is not used
        ciphertext.as_ptr(),
        ciphertext.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        nonce.as_ptr(),
        key.as_ptr()
    ) {
        log::error!("Decryption failed: {}", err);
        return Err(CryptoError::DecryptError(err.into()));
    }

    assert!(mlen as usize == plaintext.len());
    Ok(())
}
