//! Types types for dealing with (secret-) values
//!
//! These types use type level coloring to make accidential leackage of secrets extra hard. Both [Secret] and [Public] own their data, but the memory backing
//! [Secret] is special:
//! - as it is heap allocated, we can actively zeroize the memory before freeing it.
//! - guard pages before and after each allocation trap accidential sequential reads that creep towards our secrets
//! - the memory is mlocked, e.g. it is never swapped

use crate::sodium::{rng, zeroize};
use anyhow::Context;
use lazy_static::lazy_static;
use libsodium_sys as libsodium;
use rosenpass_util::{
    b64::b64_reader,
    file::{fopen_r, LoadValue, LoadValueB64, ReadExactToEnd, StoreValue},
    functional::mutating,
    mem::cpy,
};
use std::result::Result;
use std::{
    collections::HashMap,
    convert::TryInto,
    fmt,
    ops::{Deref, DerefMut},
    os::raw::c_void,
    path::Path,
    ptr::null_mut,
    sync::Mutex,
};

// This might become a problem in library usage; it's effectively a memory
// leak which probably isn't a problem right now because most memory will
// be reused…
lazy_static! {
    static ref SECRET_CACHE: Mutex<SecretMemoryPool> = Mutex::new(SecretMemoryPool::new());
}

/// Pool that stores secret memory allocations
///
/// Allocation of secret memory is expensive. Thus, this struct provides a
/// pool of secret memory, readily available to yield protected, slices of
/// memory.
///
/// Further information about the protection in place can be found in in the
/// [libsodium documentation](https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations)
#[derive(Debug)] // TODO check on Debug derive, is that clever
pub struct SecretMemoryPool {
    pool: HashMap<usize, Vec<*mut c_void>>,
}

impl SecretMemoryPool {
    /// Create a new [SecretMemoryPool]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        let pool = HashMap::new();

        Self { pool }
    }

    /// Return secrete back to the pool for future re-use
    ///
    /// This consumes the [Secret], but its memory is re-used.
    pub fn release<const N: usize>(&mut self, mut s: Secret<N>) {
        unsafe {
            self.release_by_ref(&mut s);
        }
        std::mem::forget(s);
    }

    /// Return secret back to the pool for future re-use, by slice
    ///
    /// # Safety
    ///
    /// After calling this function on a [Secret], the secret must never be
    /// used again for anything.
    unsafe fn release_by_ref<const N: usize>(&mut self, s: &mut Secret<N>) {
        s.zeroize();
        let Secret { ptr: secret } = s;
        // don't call Secret::drop, that could cause a double free
        self.pool.entry(N).or_default().push(*secret);
    }

    /// Take protected memory from the pool, allocating new one if no suitable
    /// chunk is found in the inventory.
    ///
    /// The secret is guaranteed to be full of nullbytes
    ///
    /// # Safety
    ///
    /// This function contains an unsafe call to [libsodium::sodium_malloc].
    /// This call has no known safety invariants, thus nothing can go wrong™.
    /// However, just like normal `malloc()` this can return a null ptr. Thus
    /// the returned pointer is checked for null; causing the program to panic
    /// if it is null.
    pub fn take<const N: usize>(&mut self) -> Secret<N> {
        let entry = self.pool.entry(N).or_default();
        let secret = entry.pop().unwrap_or_else(|| {
            let ptr = unsafe { libsodium::sodium_malloc(N) };
            assert!(
                !ptr.is_null(),
                "libsodium::sodium_mallloc() returned a null ptr"
            );
            ptr
        });

        let mut s = Secret { ptr: secret };
        s.zeroize();
        s
    }
}

impl Drop for SecretMemoryPool {
    /// # Safety
    ///
    /// The drop implementation frees the contained elements using
    /// [libsodium::sodium_free]. This is safe as long as every `*mut c_void`
    /// contained was initialized with a call to [libsodium::sodium_malloc]
    fn drop(&mut self) {
        for ptr in self.pool.drain().flat_map(|(_, x)| x.into_iter()) {
            unsafe {
                libsodium::sodium_free(ptr);
            }
        }
    }
}

/// # Safety
///
/// No safety implications are known, since the `*mut c_void` in
/// is essentially used like a `&mut u8` [SecretMemoryPool].
unsafe impl Send for SecretMemoryPool {}

/// Store for a secret
///
/// Uses memory allocated with [libsodium::sodium_malloc],
/// esentially can do the same things as `[u8; N].as_mut_ptr()`.
pub struct Secret<const N: usize> {
    ptr: *mut c_void,
}

impl<const N: usize> Clone for Secret<N> {
    fn clone(&self) -> Self {
        let mut new = Self::zero();
        new.secret_mut().clone_from_slice(self.secret());
        new
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.zeroize();
        // the invariant that the [Secret] is not used after the
        // `release_by_ref` call is guaranteed, since this is a drop implementation
        unsafe { SECRET_CACHE.lock().unwrap().release_by_ref(self) };
        self.ptr = null_mut();
    }
}

impl<const N: usize> Secret<N> {
    pub fn from_slice(slice: &[u8]) -> Self {
        let mut new_self = Self::zero();
        new_self.secret_mut().copy_from_slice(slice);
        new_self
    }

    /// Returns a new [Secret] that is zero initialized
    pub fn zero() -> Self {
        // Using [SecretMemoryPool] here because this operation is expensive,
        // yet it is used in hot loops
        let s = SECRET_CACHE.lock().unwrap().take();
        assert_eq!(s.secret(), &[0u8; N]);
        s
    }

    /// Returns a new [Secret] that is randomized
    pub fn random() -> Self {
        mutating(Self::zero(), |r| r.randomize())
    }

    /// Sets all data of an existing secret to null bytes
    pub fn zeroize(&mut self) {
        zeroize(self.secret_mut());
    }

    /// Sets all data an existing secret to random bytes
    pub fn randomize(&mut self) {
        rng(self.secret_mut());
    }

    /// Borrows the data
    pub fn secret(&self) -> &[u8; N] {
        // - calling `from_raw_parts` is safe, because `ptr` is initalized with
        //   as `N` byte allocation from the creation of `Secret` onwards. `ptr`
        //   stays valid over the full lifetime of `Secret`
        //
        // - calling uwnrap is safe, because we can guarantee that the slice has
        //   exactly the required size `N` to create an array of `N` elements.
        let ptr = self.ptr as *const u8;
        let slice = unsafe { std::slice::from_raw_parts(ptr, N) };
        slice.try_into().unwrap()
    }

    /// Borrows the data mutably
    pub fn secret_mut(&mut self) -> &mut [u8; N] {
        // the same safety argument as for `secret()` holds
        let ptr = self.ptr as *mut u8;
        let slice = unsafe { std::slice::from_raw_parts_mut(ptr, N) };
        slice.try_into().unwrap()
    }
}

/// The Debug implementation of [Secret] does not reveal the secret data,
/// instead a placeholder `<SECRET>` is used
impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<SECRET>")
    }
}

/// Contains information in the form of a byte array that may be known to the
/// public
// TODO: We should get rid of the Public type; just use a normal value
#[derive(Copy, Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Public<const N: usize> {
    pub value: [u8; N],
}

impl<const N: usize> Public<N> {
    /// Create a new [Public] from a byte slice
    pub fn from_slice(value: &[u8]) -> Self {
        mutating(Self::zero(), |r| cpy(value, &mut r.value))
    }

    /// Create a new [Public] from a byte array
    pub fn new(value: [u8; N]) -> Self {
        Self { value }
    }

    /// Create a zero initialized [Public]
    pub fn zero() -> Self {
        Self { value: [0u8; N] }
    }

    /// Create a random initialized [Public]
    pub fn random() -> Self {
        mutating(Self::zero(), |r| r.randomize())
    }

    /// Randomize all bytes in an existing [Public]
    pub fn randomize(&mut self) {
        rng(&mut self.value);
    }
}

/// Writes the contents of an `&[u8]` as hexadecimal symbols to a [std::fmt::Formatter]
pub fn debug_crypto_array(v: &[u8], fmt: &mut fmt::Formatter) -> fmt::Result {
    fmt.write_str("[{}]=")?;
    if v.len() > 64 {
        for byte in &v[..32] {
            std::fmt::LowerHex::fmt(byte, fmt)?;
        }
        fmt.write_str("…")?;
        for byte in &v[v.len() - 32..] {
            std::fmt::LowerHex::fmt(byte, fmt)?;
        }
    } else {
        for byte in v {
            std::fmt::LowerHex::fmt(byte, fmt)?;
        }
    }
    Ok(())
}

impl<const N: usize> fmt::Debug for Public<N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        debug_crypto_array(&self.value, fmt)
    }
}

impl<const N: usize> Deref for Public<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        &self.value
    }
}

impl<const N: usize> DerefMut for Public<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        &mut self.value
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations
    /// promises us that allocated memory is initialized with this magic byte
    const SODIUM_MAGIC_BYTE: u8 = 0xdb;

    /// must be called before any interaction with libsodium
    fn init() {
        unsafe { libsodium_sys::sodium_init() };
    }

    /// checks that whe can malloc with libsodium
    #[test]
    fn sodium_malloc() {
        init();
        const N: usize = 8;
        let ptr = unsafe { libsodium_sys::sodium_malloc(N) };
        let mem = unsafe { std::slice::from_raw_parts(ptr as *mut u8, N) };
        assert_eq!(mem, &[SODIUM_MAGIC_BYTE; N])
    }

    /// checks that whe can free with libsodium
    #[test]
    fn sodium_free() {
        init();
        const N: usize = 8;
        let ptr = unsafe { libsodium_sys::sodium_malloc(N) };
        unsafe { libsodium_sys::sodium_free(ptr) }
    }

    /// check that we can alloc using the magic pool
    #[test]
    fn secret_memory_pool_take() {
        init();
        const N: usize = 0x100;
        let mut pool = SecretMemoryPool::new();
        let secret: Secret<N> = pool.take();
        assert_eq!(secret.secret(), &[0; N]);
    }

    /// check that a secrete lives, even if its [SecretMemoryPool] is deleted
    #[test]
    fn secret_memory_pool_drop() {
        init();
        const N: usize = 0x100;
        let mut pool = SecretMemoryPool::new();
        let secret: Secret<N> = pool.take();
        std::mem::drop(pool);
        assert_eq!(secret.secret(), &[0; N]);
    }

    /// check that a secrete can be reborn, freshly initialized with zero
    #[test]
    fn secret_memory_pool_release() {
        init();
        const N: usize = 1;
        let mut pool = SecretMemoryPool::new();
        let mut secret: Secret<N> = pool.take();
        let old_secret_ptr = secret.ptr;

        secret.secret_mut()[0] = 0x13;
        pool.release(secret);

        // now check that we get the same ptr
        let new_secret: Secret<N> = pool.take();
        assert_eq!(old_secret_ptr, new_secret.ptr);

        // and that the secret was zeroized
        assert_eq!(new_secret.secret(), &[0; N]);
    }
}

trait StoreSecret {
    type Error;

    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
}

impl<T: StoreValue> StoreSecret for T {
    type Error = <T as StoreValue>::Error;

    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
        self.store(path)
    }
}

impl<const N: usize> LoadValue for Secret<N> {
    type Error = anyhow::Error;

    fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut v = Self::random();
        let p = path.as_ref();
        fopen_r(p)?
            .read_exact_to_end(v.secret_mut())
            .with_context(|| format!("Could not load file {p:?}"))?;
        Ok(v)
    }
}

impl<const N: usize> LoadValueB64 for Secret<N> {
    type Error = anyhow::Error;

    fn load_b64<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        use std::io::Read;

        let mut v = Self::random();
        let p = path.as_ref();
        // This might leave some fragments of the secret on the stack;
        // in practice this is likely not a problem because the stack likely
        // will be overwritten by something else soon but this is not exactly
        // guaranteed. It would be possible to remedy this, but since the secret
        // data will linger in the Linux page cache anyways with the current
        // implementation, going to great length to erase the secret here is
        // not worth it right now.
        b64_reader(&mut fopen_r(p)?)
            .read_exact(v.secret_mut())
            .with_context(|| format!("Could not load base64 file {p:?}"))?;
        Ok(v)
    }
}

impl<const N: usize> StoreSecret for Secret<N> {
    type Error = anyhow::Error;

    fn store_secret<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        std::fs::write(path, self.secret())?;
        Ok(())
    }
}

impl<const N: usize> LoadValue for Public<N> {
    type Error = anyhow::Error;

    fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut v = Self::random();
        fopen_r(path)?.read_exact_to_end(&mut *v)?;
        Ok(v)
    }
}

impl<const N: usize> StoreValue for Public<N> {
    type Error = anyhow::Error;

    fn store<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        std::fs::write(path, **self)?;
        Ok(())
    }
}
