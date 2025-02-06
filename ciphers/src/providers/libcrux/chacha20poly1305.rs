use rosenpass_cipher_traits::{Aead, AeadChaCha20Poly1305, AeadError as Error};
use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;

use zeroize::Zeroize;

pub const KEY_LEN: usize = 32; // Grrrr! Libcrux, please provide me these constants.
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

pub struct ChaCha20Poly1305;

impl Aead<KEY_LEN, NONCE_LEN, TAG_LEN> for ChaCha20Poly1305 {
    fn encrypt(
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), Error> {
        let (ciphertext, mac) = ciphertext.split_at_mut(ciphertext.len() - TAG_LEN);
        let (ctxt, tag) = libcrux_chacha20poly1305::encrypt(key, plaintext, ciphertext, ad, nonce)
            .map_err(|_| Error::InternalError)?;
        copy_slice(tag).to(mac);

        // return an error of the destination buffer is longer than expected
        // because the caller wouldn't know where the end is
        if ctxt.len() + tag.len() != ciphertext.len() {
            return Error::InternalError;
        }

        Ok(())
    }

    fn decrypt(
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let ptxt = libcrux_chacha20poly1305::decrypt(key, plaintext, ciphertext, ad, nonce)
            .map_err(|_| Error::DecryptError)?;

        // return an error of the destination buffer is longer than expected
        // because the caller wouldn't know where the end is
        if ptxt.len() != plaintext.len() {
            return Error::DecryptError;
        }

        Ok(())
    }
}

impl AeadChaCha20Poly1305 for ChaCha20Poly1305 {}
