use libsodium_sys as libsodium;
use std::ffi::c_ulonglong;
use std::ptr::{null, null_mut};
use log::{error, info};
use thiserror::Error;

pub const KEY_LEN: usize = libsodium::crypto_aead_xchacha20poly1305_IETF_KEYBYTES as usize;
pub const TAG_LEN: usize = libsodium::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
pub const NONCE_LEN: usize = libsodium::crypto_aead_xchacha20poly1305_IETF_NPUBBYTES as usize;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption error: {0}")]
    EncryptionError(#[from] log::Error),
    
    #[error("Decryption error: {0}")]
    DecryptionError(#[from] log::Error),
}

#[inline]
pub fn encrypt(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<(), CryptoError> {
    assert!(ciphertext.len() == plaintext.len() + NONCE_LEN + TAG_LEN);
    assert!(key.len() == libsodium::crypto_aead_xchacha20poly1305_IETF_KEYBYTES as usize);
    let (n, ct) = ciphertext.split_at_mut(NONCE_LEN);
    n.copy_from_slice(nonce);
    let mut clen: u64 = 0;
    
    match sodium_call!(
        crypto_aead_xchacha20poly1305_ietf_encrypt,
        ct.as_mut_ptr(),
        &mut clen,
        plaintext.as_ptr(),
        plaintext.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        null(), // nsec is not used
        nonce.as_ptr(),
        key.as_ptr()
    ) {
        Ok(()) => {
            assert!(clen as usize == ct.len());
            Ok(())
        },
        Err(err) => {
            error!("Encryption failed: {}", err);
            Err(CryptoError::EncryptionError(log::Error))
        },
    }
}

#[inline]
pub fn decrypt(
    plaintext: &mut [u8],
    key: &[u8],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<(), CryptoError> {
    assert!(ciphertext.len() == plaintext.len() + NONCE_LEN + TAG_LEN);
    assert!(key.len() == KEY_LEN);
    let (n, ct) = ciphertext.split_at(NONCE_LEN);
    let mut mlen: u64 = 0;
    
    match sodium_call!(
        crypto_aead_xchacha20poly1305_ietf_decrypt,
        plaintext.as_mut_ptr(),
        &mut mlen as *mut c_ulonglong,
        null_mut(), // nsec is not used
        ct.as_ptr(),
        ct.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        n.as_ptr(),
        key.as_ptr()
    ) {
        Ok(()) => {
            assert!(mlen as usize == plaintext.len());
            Ok(())
        },
        Err(err) => {
            error!("Decryption failed: {}", err);
            Err(CryptoError::DecryptionError(log::Error))
        },
    }
}
