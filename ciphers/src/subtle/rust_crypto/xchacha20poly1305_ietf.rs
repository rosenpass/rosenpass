use rosenpass_cipher_traits::primitives::{Aead, AeadError, AeadWithNonceInCiphertext};
use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;
use rosenpass_util::typenum2const;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::XChaCha20Poly1305 as AeadImpl;
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};

/// The key length is 32 bytes or 256 bits.
pub const KEY_LEN: usize = typenum2const! { <AeadImpl as KeySizeUser>::KeySize };
/// The  MAC tag length is 16 bytes or 128 bits.
pub const TAG_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::TagSize };
/// The nonce length is 24 bytes or 192 bits.
pub const NONCE_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::NonceSize };

pub struct XChaCha20Poly1305;

impl Aead<KEY_LEN, NONCE_LEN, TAG_LEN> for XChaCha20Poly1305 {
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

        let (ct, mac) = ciphertext.split_at_mut(ciphertext.len() - TAG_LEN);
        copy_slice(plaintext).to(ct);

        let nonce = GenericArray::from_slice(nonce);

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

        let (ct, mac) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
        let nonce = GenericArray::from_slice(nonce);
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

/// Encrypts using XChaCha20Poly1305 as implemented in [RustCrypto](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305).
/// `key` and `nonce` MUST be chosen (pseudo-)randomly. The `key` slice MUST have a length of
/// [KEY_LEN]. The `nonce` slice MUST have a length of [NONCE_LEN].
/// In contrast to [chacha20poly1305_ietf::encrypt](crate::subtle::chacha20poly1305_ietf::encrypt) and
/// [chacha20poly1305_ietf_libcrux::encrypt](crate::subtle::chacha20poly1305_ietf_libcrux::encrypt),
/// `nonce` is also written into `ciphertext` and therefore ciphertext MUST have a length
/// of at least [NONCE_LEN] + `plaintext.len()` + [TAG_LEN].
///
/// # Examples
///```rust
/// # use rosenpass_ciphers::subtle::xchacha20poly1305_ietf::{encrypt, TAG_LEN, KEY_LEN, NONCE_LEN};
/// const PLAINTEXT_LEN: usize = 43;
/// let plaintext = "post-quantum cryptography is very important".as_bytes();
/// assert_eq!(PLAINTEXT_LEN, plaintext.len());
/// let key: &[u8] = &[0u8; KEY_LEN]; // THIS IS NOT A SECURE KEY
/// let nonce: &[u8] = &[0u8; NONCE_LEN]; // THIS IS NOT A SECURE NONCE
/// let additional_data: &[u8] = "the encrypted message is very important".as_bytes();
/// let mut ciphertext_buffer = [0u8; NONCE_LEN + PLAINTEXT_LEN + TAG_LEN];
///
///
/// let res: anyhow::Result<()> = encrypt(&mut ciphertext_buffer, key, nonce, additional_data, plaintext);
/// # assert!(res.is_ok());
/// # let expected_ciphertext: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/// # 0, 0, 0, 0, 8, 241, 229, 253, 200, 81, 248, 30, 183, 149, 134, 168, 149, 87, 109, 49, 159, 108,
/// # 206, 89, 51, 232, 232, 197, 163, 253, 254, 208, 73, 76, 253, 13, 247, 162, 133, 184, 177, 44,
/// # 73, 138, 176, 193, 61, 248, 61, 183, 164, 192, 214, 168, 4, 1, 62, 243, 36, 48, 149, 164, 6];
/// # assert_eq!(expected_ciphertext, &ciphertext_buffer);
///```
#[inline]
pub fn encrypt(
    ciphertext: &mut [u8],
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<()> {
    XChaCha20Poly1305
        .encrypt(ciphertext, key, nonce, ad, plaintext)
        .map_err(anyhow::Error::from)
}

/// Decrypts a `ciphertext` and verifies the integrity of the `ciphertext` and the additional data
/// `ad`. using XChaCha20Poly1305 as implemented in [RustCrypto](https://github.com/RustCrypto/AEADs/tree/master/chacha20poly1305).
///
/// The `key` slice MUST have a length of [KEY_LEN]. The `nonce` slice MUST have a length of
/// [NONCE_LEN]. The plaintext buffer must have a capacity of `ciphertext.len()` - [TAG_LEN] - [NONCE_LEN].
///
/// In contrast to [chacha20poly1305_ietf::decrypt](crate::subtle::chacha20poly1305_ietf::decrypt) and
/// [chacha20poly1305_ietf_libcrux::decrypt](crate::subtle::chacha20poly1305_ietf_libcrux::decrypt),
/// `ciperhtext` MUST include the as it is not given otherwise.
///
/// # Examples
///```rust
/// # use rosenpass_ciphers::subtle::xchacha20poly1305_ietf::{decrypt, TAG_LEN, KEY_LEN, NONCE_LEN};
/// let ciphertext: &[u8] = &[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
/// # 0, 0, 0, 0, 8, 241, 229, 253, 200, 81, 248, 30, 183, 149, 134, 168, 149, 87, 109, 49, 159, 108,
/// # 206, 89, 51, 232, 232, 197, 163, 253, 254, 208, 73, 76, 253, 13, 247, 162, 133, 184, 177, 44,
/// # 73, 138, 176, 193, 61, 248, 61, 183, 164, 192, 214, 168, 4, 1, 62, 243, 36, 48, 149, 164, 6];
/// // this is the ciphertext generated by the example for the encryption
/// const PLAINTEXT_LEN: usize = 43;
/// assert_eq!(PLAINTEXT_LEN + TAG_LEN + NONCE_LEN, ciphertext.len());
///
/// let key: &[u8] = &[0u8; KEY_LEN]; // THIS IS NOT A SECURE KEY
/// let nonce: &[u8] = &[0u8; NONCE_LEN]; // THIS IS NOT A SECURE NONCE
/// let additional_data: &[u8] = "the encrypted message is very important".as_bytes();
/// let mut plaintext_buffer = [0u8; PLAINTEXT_LEN];
///
/// let res: anyhow::Result<()> = decrypt(&mut plaintext_buffer, key, additional_data, ciphertext);
/// assert!(res.is_ok());
/// let expected_plaintext = "post-quantum cryptography is very important".as_bytes();
/// assert_eq!(expected_plaintext, plaintext_buffer);
///
///```
#[inline]
pub fn decrypt(
    plaintext: &mut [u8],
    key: &[u8; KEY_LEN],
    ad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<()> {
    XChaCha20Poly1305
        .decrypt_with_nonce_in_ctxt(plaintext, key, ad, ciphertext)
        .map_err(anyhow::Error::from)
}
