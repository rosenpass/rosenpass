use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;

pub use rosenpass_cipher_traits::aead_chacha20poly1305::{KEY_LEN, NONCE_LEN, TAG_LEN};
use rosenpass_cipher_traits::{Aead, AeadChaCha20Poly1305, AeadError};

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::ChaCha20Poly1305 as AeadImpl;
use chacha20poly1305::{AeadInPlace, KeyInit};

pub struct ChaCha20Poly1305;

impl Aead<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20Poly1305 {
    fn encrypt(
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AeadError> {
        let nonce = GenericArray::from_slice(nonce);
        let (ct, mac) = ciphertext.split_at_mut(ciphertext.len() - TAG_LEN);
        copy_slice(plaintext).to(ct);
        let mac_value = AeadImpl::new_from_slice(key)
            .map_err(|_| AeadError::InternalError)?
            .encrypt_in_place_detached(nonce, ad, ct)
            .map_err(|_| AeadError::InternalError)?;
        copy_slice(&mac_value[..]).to(mac);
        Ok(())
    }

    fn decrypt(
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), AeadError> {
        let nonce = GenericArray::from_slice(nonce);
        let (ct, mac) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let tag = GenericArray::from_slice(mac);
        copy_slice(ct).to(plaintext);
        AeadImpl::new_from_slice(key)
            .map_err(|_| AeadError::InternalError)?
            .decrypt_in_place_detached(nonce, ad, plaintext, tag)
            .map_err(|_| AeadError::DecryptError)?;
        Ok(())
    }
}

impl AeadChaCha20Poly1305 for ChaCha20Poly1305 {}
