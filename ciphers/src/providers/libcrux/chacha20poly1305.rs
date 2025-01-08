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

        use libcrux::aead as C;
        let crux_key = C::Key::Chacha20Poly1305(C::Chacha20Key(key.to_owned()));
        let crux_iv = C::Iv(nonce.to_owned());

        copy_slice(plaintext).to(ciphertext);
        let crux_tag = libcrux::aead::encrypt(&crux_key, ciphertext, crux_iv, ad)
            .map_err(|_| Error::InternalError)?;
        copy_slice(crux_tag.as_ref()).to(mac);

        match crux_key {
            C::Key::Chacha20Poly1305(mut k) => k.0.zeroize(),
            _ => unreachable!(),
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

        use libcrux::aead as C;
        let crux_key = C::Key::Chacha20Poly1305(C::Chacha20Key(key.to_owned()));
        let crux_iv = C::Iv(nonce.to_owned());
        let crux_tag = C::Tag::from_slice(mac).unwrap();

        copy_slice(ciphertext).to(plaintext);
        libcrux::aead::decrypt(&crux_key, plaintext, crux_iv, ad, &crux_tag).map_err(|err| {
            match err {
                C::Error::DecryptionFailed => Error::DecryptError,
                _ => Error::InternalError,
            }
        })?;

        match crux_key {
            C::Key::Chacha20Poly1305(mut k) => k.0.zeroize(),
            _ => unreachable!(),
        }

        Ok(())
    }
}

impl AeadChaCha20Poly1305 for ChaCha20Poly1305 {}
