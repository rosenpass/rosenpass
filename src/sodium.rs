//! Bindings and helpers for accessing libsodium functions

use crate::util::*;
use anyhow::{ensure, Result};
use libsodium_sys as libsodium;
use log::trace;
use static_assertions::const_assert_eq;
use std::os::raw::{c_ulonglong, c_void};
use std::ptr::{null as nullptr, null_mut as nullptr_mut};

pub const AEAD_TAG_LEN: usize = libsodium::crypto_aead_chacha20poly1305_IETF_ABYTES as usize;
pub const AEAD_NONCE_LEN: usize = libsodium::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize;
pub const XAEAD_TAG_LEN: usize = libsodium::crypto_aead_xchacha20poly1305_ietf_ABYTES as usize;
pub const XAEAD_NONCE_LEN: usize = libsodium::crypto_aead_xchacha20poly1305_IETF_NPUBBYTES as usize;
pub const NONCE0: [u8; libsodium::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize] =
    [0u8; libsodium::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize];
pub const NOTHING: [u8; 0] = [0u8; 0];
pub const KEY_SIZE: usize = 32;
pub const MAC_SIZE: usize = 16;

const_assert_eq!(
    KEY_SIZE,
    libsodium::crypto_aead_chacha20poly1305_IETF_KEYBYTES as usize
);
const_assert_eq!(KEY_SIZE, libsodium::crypto_generichash_BYTES as usize);

macro_rules! sodium_call {
    ($name:ident, $($args:expr),*) => { attempt!({
        ensure!(unsafe{libsodium::$name($($args),*)} > -1,
            "Error in libsodium's {}.", stringify!($name));
        Ok(())
    })};
    ($name:ident) => { sodium_call!($name, ) };
}

#[inline]
pub fn sodium_init() -> Result<()> {
    trace!("initializing libsodium");
    sodium_call!(sodium_init)
}

#[inline]
pub fn sodium_memcmp(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && unsafe {
            let r = libsodium::sodium_memcmp(
                a.as_ptr() as *const c_void,
                b.as_ptr() as *const c_void,
                a.len(),
            );
            r == 0
        }
}

#[inline]
pub fn sodium_bigint_cmp(a: &[u8], b: &[u8]) -> i32 {
    assert!(a.len() == b.len());
    unsafe { libsodium::sodium_compare(a.as_ptr(), b.as_ptr(), a.len()) }
}

#[inline]
pub fn sodium_bigint_inc(v: &mut [u8]) {
    unsafe {
        libsodium::sodium_increment(v.as_mut_ptr(), v.len());
    }
}

#[inline]
pub fn rng(buf: &mut [u8]) {
    unsafe { libsodium::randombytes_buf(buf.as_mut_ptr() as *mut c_void, buf.len()) };
}

#[inline]
pub fn zeroize(buf: &mut [u8]) {
    unsafe { libsodium::sodium_memzero(buf.as_mut_ptr() as *mut c_void, buf.len()) };
}

#[inline]
pub fn aead_enc_into(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<()> {
    assert!(ciphertext.len() == plaintext.len() + AEAD_TAG_LEN);
    assert!(key.len() == libsodium::crypto_aead_chacha20poly1305_IETF_KEYBYTES as usize);
    assert!(nonce.len() == libsodium::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize);
    let mut clen: u64 = 0;
    sodium_call!(
        crypto_aead_chacha20poly1305_ietf_encrypt,
        ciphertext.as_mut_ptr(),
        &mut clen,
        plaintext.as_ptr(),
        plaintext.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        nullptr(), // nsec is not used
        nonce.as_ptr(),
        key.as_ptr()
    )?;
    assert!(clen as usize == ciphertext.len());
    Ok(())
}

#[inline]
pub fn aead_dec_into(
    plaintext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    assert!(ciphertext.len() == plaintext.len() + AEAD_TAG_LEN);
    assert!(key.len() == libsodium::crypto_aead_chacha20poly1305_IETF_KEYBYTES as usize);
    assert!(nonce.len() == libsodium::crypto_aead_chacha20poly1305_IETF_NPUBBYTES as usize);
    let mut mlen: u64 = 0;
    sodium_call!(
        crypto_aead_chacha20poly1305_ietf_decrypt,
        plaintext.as_mut_ptr(),
        &mut mlen as *mut c_ulonglong,
        nullptr_mut(), // nsec is not used
        ciphertext.as_ptr(),
        ciphertext.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        nonce.as_ptr(),
        key.as_ptr()
    )?;
    assert!(mlen as usize == plaintext.len());
    Ok(())
}

#[inline]
pub fn xaead_enc_into(
    ciphertext: &mut [u8],
    key: &[u8],
    nonce: &[u8],
    ad: &[u8],
    plaintext: &[u8],
) -> Result<()> {
    assert!(ciphertext.len() == plaintext.len() + XAEAD_NONCE_LEN + XAEAD_TAG_LEN);
    assert!(key.len() == libsodium::crypto_aead_xchacha20poly1305_IETF_KEYBYTES as usize);
    let (n, ct) = ciphertext.split_at_mut(XAEAD_NONCE_LEN);
    n.copy_from_slice(nonce);
    let mut clen: u64 = 0;
    sodium_call!(
        crypto_aead_xchacha20poly1305_ietf_encrypt,
        ct.as_mut_ptr(),
        &mut clen,
        plaintext.as_ptr(),
        plaintext.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        nullptr(), // nsec is not used
        nonce.as_ptr(),
        key.as_ptr()
    )?;
    assert!(clen as usize == ct.len());
    Ok(())
}

#[inline]
pub fn xaead_dec_into(
    plaintext: &mut [u8],
    key: &[u8],
    ad: &[u8],
    ciphertext: &[u8],
) -> Result<()> {
    assert!(ciphertext.len() == plaintext.len() + XAEAD_NONCE_LEN + XAEAD_TAG_LEN);
    assert!(key.len() == libsodium::crypto_aead_xchacha20poly1305_IETF_KEYBYTES as usize);
    let (n, ct) = ciphertext.split_at(XAEAD_NONCE_LEN);
    let mut mlen: u64 = 0;
    sodium_call!(
        crypto_aead_xchacha20poly1305_ietf_decrypt,
        plaintext.as_mut_ptr(),
        &mut mlen as *mut c_ulonglong,
        nullptr_mut(), // nsec is not used
        ct.as_ptr(),
        ct.len() as c_ulonglong,
        ad.as_ptr(),
        ad.len() as c_ulonglong,
        n.as_ptr(),
        key.as_ptr()
    )?;
    assert!(mlen as usize == plaintext.len());
    Ok(())
}

#[inline]
fn blake2b_flexible(out: &mut [u8], key: &[u8], data: &[u8]) -> Result<()> {
    const KEY_MIN: usize = libsodium::crypto_generichash_KEYBYTES_MIN as usize;
    const KEY_MAX: usize = libsodium::crypto_generichash_KEYBYTES_MAX as usize;
    const OUT_MIN: usize = libsodium::crypto_generichash_BYTES_MIN as usize;
    const OUT_MAX: usize = libsodium::crypto_generichash_BYTES_MAX as usize;
    assert!(key.is_empty() || (KEY_MIN <= key.len() && key.len() <= KEY_MAX));
    assert!(OUT_MIN <= out.len() && out.len() <= OUT_MAX);
    let kptr = match key.len() {
        // NULL key
        0 => nullptr(),
        _ => key.as_ptr(),
    };
    sodium_call!(
        crypto_generichash_blake2b,
        out.as_mut_ptr(),
        out.len(),
        data.as_ptr(),
        data.len() as c_ulonglong,
        kptr,
        key.len()
    )
}

// TODO: Use proper streaming hash; for mix_hash too.
#[inline]
pub fn hash_into(out: &mut [u8], data: &[u8]) -> Result<()> {
    assert!(out.len() == KEY_SIZE);
    blake2b_flexible(out, &NOTHING, data)
}

#[inline]
pub fn hash(data: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut r = [0u8; KEY_SIZE];
    hash_into(&mut r, data)?;
    Ok(r)
}

#[inline]
pub fn mac_into(out: &mut [u8], key: &[u8], data: &[u8]) -> Result<()> {
    assert!(out.len() == KEY_SIZE);
    assert!(key.len() == KEY_SIZE);
    blake2b_flexible(out, key, data)
}

#[inline]
pub fn mac(key: &[u8], data: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut r = [0u8; KEY_SIZE];
    mac_into(&mut r, key, data)?;
    Ok(r)
}

#[inline]
pub fn mac16(key: &[u8], data: &[u8]) -> Result<[u8; 16]> {
    assert!(key.len() == KEY_SIZE);
    let mut out = [0u8; 16];
    blake2b_flexible(&mut out, key, data)?;
    Ok(out)
}

#[inline]
pub fn hmac_into(out: &mut [u8], key: &[u8], data: &[u8]) -> Result<()> {
    // Not bothering with padding; the implementation
    // uses appropriately sized keys.
    ensure!(key.len() == KEY_SIZE);

    const IPAD: [u8; KEY_SIZE] = [0x36u8; KEY_SIZE];
    let mut temp_key = [0u8; KEY_SIZE];
    temp_key.copy_from_slice(key);
    xor_into(&mut temp_key, &IPAD);
    let outer_data = mac(&temp_key, data)?;

    const OPAD: [u8; KEY_SIZE] = [0x5Cu8; KEY_SIZE];
    temp_key.copy_from_slice(key);
    xor_into(&mut temp_key, &OPAD);
    mac_into(out, &temp_key, &outer_data)
}

#[inline]
pub fn hmac(key: &[u8], data: &[u8]) -> Result<[u8; KEY_SIZE]> {
    let mut r = [0u8; KEY_SIZE];
    hmac_into(&mut r, key, data)?;
    Ok(r)
}

// Choose a fully random u64
pub fn rand_u64() -> u64 {
    let mut buf = [0u8; 8];
    rng(&mut buf);
    u64::from_le_bytes(buf)
}

// Choose a random f64 in [0; 1] inclusive; quick and dirty
pub fn rand_f64() -> f64 {
    (rand_u64() as f64) / (u64::MAX as f64)
}
