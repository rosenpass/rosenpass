use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;

use rosenpass_cipher_traits::algorithms::AeadChaCha20Poly1305;
use rosenpass_cipher_traits::primitives::{Aead, AeadError};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::ChaCha20Poly1305 as AeadImpl;
use chacha20poly1305::{AeadInPlace, KeyInit};

pub use rosenpass_cipher_traits::algorithms::aead_chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN};

/// Implements the [`Aead`] and [`AeadChaCha20Poly1305`] traits backed by the RustCrypto
/// implementation.
pub struct ChaCha20Poly1305;

impl Aead<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20Poly1305 {
    fn encrypt(
        &self,
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AeadError> {
        // The comparison looks complicated, but we need to do it this way to prevent
        // over/underflows.
        if ciphertext.len() < TAG_LEN || ciphertext.len() - TAG_LEN < plaintext.len() {
            return Err(AeadError::InvalidLengths);
        }

        let nonce = GenericArray::from_slice(nonce);
        let (ct, mac) = ciphertext.split_at_mut(ciphertext.len() - TAG_LEN);
        copy_slice(plaintext).to(ct);

        // This only fails if the length is wrong, which really shouldn't happen and would
        // constitute an internal error.
        let encrypter = AeadImpl::new_from_slice(key).map_err(|_| AeadError::InternalError)?;

        let mac_value = encrypter
            .encrypt_in_place_detached(nonce, ad, ct)
            .map_err(|_| AeadError::InternalError)?;
        copy_slice(&mac_value[..]).to(mac);

        Ok(())
    }

    fn decrypt(
        &self,
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), AeadError> {
        // The comparison looks complicated, but we need to do it this way to prevent
        // over/underflows.
        if ciphertext.len() < TAG_LEN || ciphertext.len() - TAG_LEN < plaintext.len() {
            return Err(AeadError::InvalidLengths);
        }

        let nonce = GenericArray::from_slice(nonce);
        let (ct, mac) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let tag = GenericArray::from_slice(mac);
        copy_slice(ct).to(plaintext);

        // This only fails if the length is wrong, which really shouldn't happen and would
        // constitute an internal error.
        let decrypter = AeadImpl::new_from_slice(key).map_err(|_| AeadError::InternalError)?;

        decrypter
            .decrypt_in_place_detached(nonce, ad, plaintext, tag)
            .map_err(|_| AeadError::DecryptError)?;

        Ok(())
    }
}

impl AeadChaCha20Poly1305 for ChaCha20Poly1305 {}
