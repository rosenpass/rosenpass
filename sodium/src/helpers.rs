use libsodium_sys as libsodium;
use std::os::raw::c_void;

#[inline]
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
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
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    assert!(a.len() == b.len());
    unsafe { libsodium::sodium_compare(a.as_ptr(), b.as_ptr(), a.len()) }
}

#[inline]
pub fn increment(v: &mut [u8]) {
    unsafe {
        libsodium::sodium_increment(v.as_mut_ptr(), v.len());
    }
}

#[inline]
pub fn randombytes_buf(buf: &mut [u8]) {
    unsafe { libsodium::randombytes_buf(buf.as_mut_ptr() as *mut c_void, buf.len()) };
}

#[inline]
pub fn memzero(buf: &mut [u8]) {
    unsafe { libsodium::sodium_memzero(buf.as_mut_ptr() as *mut c_void, buf.len()) };
}

// Choose a fully random u64
// TODO: Replace with ::rand::random
pub fn rand_u64() -> u64 {
    let mut buf = [0u8; 8];
    randombytes_buf(&mut buf);
    u64::from_le_bytes(buf)
}

// Choose a random f64 in [0; 1] inclusive; quick and dirty
// TODO: Replace with ::rand::random
pub fn rand_f64() -> f64 {
    (rand_u64() as f64) / (u64::MAX as f64)
}
