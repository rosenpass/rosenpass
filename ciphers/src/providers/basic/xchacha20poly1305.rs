use rosenpass_cipher_traits::{Aead, AeadError, AeadXChaCha20Poly1305};
use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;
use rosenpass_util::typenum2const;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::XChaCha20Poly1305 as AeadImpl;
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};

pub const KEY_LEN: usize = typenum2const! { <AeadImpl as KeySizeUser>::KeySize };
pub const TAG_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::TagSize };
pub const NONCE_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::NonceSize };

pub struct XChaCha20Poly1305;

impl Aead<KEY_LEN, NONCE_LEN, TAG_LEN> for XChaCha20Poly1305 {
    fn encrypt(
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), AeadError> {
        let nonce = GenericArray::from_slice(nonce);
        let (n, ct_mac) = ciphertext.split_at_mut(NONCE_LEN);
        let (ct, mac) = ct_mac.split_at_mut(ct_mac.len() - TAG_LEN);
        copy_slice(nonce).to(n);
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

impl AeadXChaCha20Poly1305 for XChaCha20Poly1305 {}
