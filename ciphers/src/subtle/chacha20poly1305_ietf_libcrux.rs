use rosenpass_to::ops::copy_slice;
use rosenpass_to::To;

use zeroize::Zeroize;

pub const KEY_LEN: usize = 32; // Grrrr! Libcrux, please provide me these constants.
pub const TAG_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;

#[inline]
pub fn encrypt(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<()> {
    let (ciphertext, mac) = ciphertext.split_at_mut(ciphertext.len() - TAG_LEN);

    use libcrux::aead as C;
    let crux_key = C::Key::Chacha20Poly1305(C::Chacha20Key(key.try_into().unwrap()));
    let crux_iv = C::Iv(nonce.try_into().unwrap());

    copy_slice(plaintext).to(ciphertext);
    let crux_tag = libcrux::aead::encrypt(&crux_key, ciphertext, crux_iv, ad).unwrap();
    copy_slice(crux_tag.as_ref()).to(mac);

    match crux_key {
        C::Key::Chacha20Poly1305(mut k) => k.0.zeroize(),
        _ => panic!(),
    }

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
    let (ciphertext, mac) = ciphertext.split_at(ciphertext.len() - TAG_LEN);

    use libcrux::aead as C;
    let crux_key = C::Key::Chacha20Poly1305(C::Chacha20Key(key.try_into().unwrap()));
    let crux_iv = C::Iv(nonce.try_into().unwrap());
    let crux_tag = C::Tag::from_slice(mac).unwrap();

    copy_slice(ciphertext).to(plaintext);
    libcrux::aead::decrypt(&crux_key, plaintext, crux_iv, ad, &crux_tag).unwrap();

    match crux_key {
        C::Key::Chacha20Poly1305(mut k) => k.0.zeroize(),
        _ => panic!(),
    }

    Ok(())
}
