use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;
use rosenpass_util::typenum2const;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::ChaCha20Poly1305 as AeadImpl;
use chacha20poly1305::{AeadCore, AeadInPlace, KeyInit, KeySizeUser};

pub const KEY_LEN: usize = typenum2const! { <AeadImpl as KeySizeUser>::KeySize };
pub const TAG_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::TagSize };
pub const NONCE_LEN: usize = typenum2const! { <AeadImpl as AeadCore>::NonceSize };

#[inline]
pub fn encrypt(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<()> {
    let nonce = GenericArray::from_slice(nonce);
    let (ct, mac) = ciphertext.split_at_mut(ciphertext.len() - TAG_LEN);
    copy_slice(plaintext).to(ct);
    let mac_value = AeadImpl::new_from_slice(key)?.encrypt_in_place_detached(nonce, ad, ct)?;
    copy_slice(&mac_value[..]).to(mac);
    Ok(())
}

#[inline]
pub fn decrypt(
    plaintext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    ciphertext: &[u8],
) -> anyhow::Result<()> {
    let nonce = GenericArray::from_slice(nonce);
    let (ct, mac) = ciphertext.split_at(ciphertext.len() - TAG_LEN);
    let tag = GenericArray::from_slice(mac);
    copy_slice(ct).to(plaintext);
    AeadImpl::new_from_slice(key)?.decrypt_in_place_detached(nonce, ad, plaintext, tag)?;
    Ok(())
}
