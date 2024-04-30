use std::cell::RefCell;
use std::collections::HashMap;
use std::convert::TryInto;
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::Path;

use anyhow::Context;
use rand::{Fill as Randomize, Rng};
use zeroize::{Zeroize, ZeroizeOnDrop};

use rosenpass_util::b64::b64_reader;
use rosenpass_util::file::{fopen_r, LoadValue, LoadValueB64, ReadExactToEnd};
use rosenpass_util::functional::mutating;

use crate::alloc::{secret_box, SecretBox, SecretVec};
use crate::file::StoreSecret;

use rosenpass_util::file::{fopen_w, Visibility};
use std::io::Write;
// This might become a problem in library usage; it's effectively a memory
// leak which probably isn't a problem right now because most memory will
// be reused…
thread_local! {
    static SECRET_CACHE: RefCell<SecretMemoryPool> = RefCell::new(SecretMemoryPool::new());
}

fn with_secret_memory_pool<Fn, R>(mut f: Fn) -> R
where
    Fn: FnMut(Option<&mut SecretMemoryPool>) -> R,
{
    // This acquires the SECRET_CACHE
    SECRET_CACHE
        .try_with(|cell| {
            // And acquires the inner reference
            cell.try_borrow_mut()
                .as_deref_mut()
                // To call the given function
                .map(|pool| f(Some(pool)))
                .ok()
        })
        .ok()
        .flatten()
        // Failing that, the given function is called with None
        .unwrap_or_else(|| f(None))
}

// Wrapper around SecretBox that applies automatic zeroization
#[derive(Debug)]
struct ZeroizingSecretBox<T: Zeroize + ?Sized>(Option<SecretBox<T>>);

impl<T: Zeroize> ZeroizingSecretBox<T> {
    fn new(boxed: T) -> Self {
        ZeroizingSecretBox(Some(secret_box(boxed)))
    }
}

impl<T: Zeroize + ?Sized> ZeroizingSecretBox<T> {
    fn from_secret_box(inner: SecretBox<T>) -> Self {
        Self(Some(inner))
    }

    fn take(mut self) -> SecretBox<T> {
        self.0.take().unwrap()
    }
}

impl<T: Zeroize + ?Sized> ZeroizeOnDrop for ZeroizingSecretBox<T> {}
impl<T: Zeroize + ?Sized> Zeroize for ZeroizingSecretBox<T> {
    fn zeroize(&mut self) {
        if let Some(inner) = &mut self.0 {
            let inner: &mut SecretBox<T> = inner; // type annotation
            inner.zeroize()
        }
    }
}

impl<T: Zeroize + ?Sized> Drop for ZeroizingSecretBox<T> {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl<T: Zeroize + ?Sized> Deref for ZeroizingSecretBox<T> {
    type Target = T;

    fn deref(&self) -> &T {
        self.0.as_ref().unwrap()
    }
}

impl<T: Zeroize + ?Sized> DerefMut for ZeroizingSecretBox<T> {
    fn deref_mut(&mut self) -> &mut T {
        self.0.as_mut().unwrap()
    }
}

/// Pool that stores secret memory allocations
///
/// Allocation of secret memory is expensive. Thus, this struct provides a
/// pool of secret memory, readily available to yield protected, slices of
/// memory.
#[derive(Debug)] // TODO check on Debug derive, is that clever
struct SecretMemoryPool {
    pool: HashMap<usize, Vec<ZeroizingSecretBox<[u8]>>>,
}

impl SecretMemoryPool {
    /// Create a new [SecretMemoryPool]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            pool: HashMap::new(),
        }
    }

    /// Return secret back to the pool for future re-use
    pub fn release<const N: usize>(&mut self, mut sec: ZeroizingSecretBox<[u8; N]>) {
        sec.zeroize();

        // This conversion sequence is weird but at least it guarantees
        // that the heap allocation is preserved according to the docs
        let sec: SecretVec<u8> = sec.take().into();
        let sec: SecretBox<[u8]> = sec.into();

        self.pool
            .entry(N)
            .or_default()
            .push(ZeroizingSecretBox::from_secret_box(sec));
    }

    /// Take protected memory from the pool, allocating new one if no suitable
    /// chunk is found in the inventory.
    ///
    /// The secret is guaranteed to be full of nullbytes
    pub fn take<const N: usize>(&mut self) -> ZeroizingSecretBox<[u8; N]> {
        let entry = self.pool.entry(N).or_default();
        let inner = match entry.pop() {
            None => secret_box([0u8; N]),
            Some(sec) => sec.take().try_into().unwrap(),
        };
        ZeroizingSecretBox::from_secret_box(inner)
    }
}

/// Storage for secret data
pub struct Secret<const N: usize> {
    storage: Option<ZeroizingSecretBox<[u8; N]>>,
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
        let buf = with_secret_memory_pool(|pool| {
            pool.map(|p| p.take())
                .unwrap_or_else(|| ZeroizingSecretBox::new([0u8; N]))
        });

        Self { storage: Some(buf) }
    }

    /// Returns a new [Secret] that is randomized
    pub fn random() -> Self {
        mutating(Self::zero(), |r| r.randomize())
    }

    /// Sets all data an existing secret to random bytes
    pub fn randomize(&mut self) {
        self.try_fill(&mut crate::rand::rng()).unwrap()
    }

    /// Borrows the data
    pub fn secret(&self) -> &[u8; N] {
        self.storage.as_ref().unwrap()
    }

    /// Borrows the data mutably
    pub fn secret_mut(&mut self) -> &mut [u8; N] {
        self.storage.as_mut().unwrap()
    }
}

impl<const N: usize> Randomize for Secret<N> {
    fn try_fill<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Result<(), rand::Error> {
        // Zeroize self first just to make sure the barriers from the zeroize create take
        // effect to prevent the compiler from optimizing this away.
        // We should at some point replace this with our own barriers.
        self.zeroize();
        self.secret_mut().try_fill(rng)
    }
}

impl<const N: usize> ZeroizeOnDrop for Secret<N> {}
impl<const N: usize> Zeroize for Secret<N> {
    fn zeroize(&mut self) {
        if let Some(inner) = &mut self.storage {
            inner.zeroize()
        }
    }
}

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        with_secret_memory_pool(|pool| {
            if let Some((pool, secret)) = pool.zip(self.storage.take()) {
                pool.release(secret);
            }
        });

        // This should be unnecessary: The pool has one item – the inner secret – which
        // zeroizes itself on drop. Calling it should not do any harm though…
        self.zeroize()
    }
}

impl<const N: usize> Clone for Secret<N> {
    fn clone(&self) -> Self {
        Self::from_slice(self.secret())
    }
}

/// The Debug implementation of [Secret] does not reveal the secret data,
/// instead a placeholder `<SECRET>` is used
impl<const N: usize> fmt::Debug for Secret<N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<SECRET>")
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
        fopen_w(path, Visibility::Secret)?.write_all(self.secret())?;
        Ok(())
    }

    fn store<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        fopen_w(path, Visibility::Public)?.write_all(self.secret())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// check that we can alloc using the magic pool
    #[test]
    fn secret_memory_pool_take() {
        const N: usize = 0x100;
        let mut pool = SecretMemoryPool::new();
        let secret: ZeroizingSecretBox<[u8; N]> = pool.take();
        assert_eq!(secret.as_ref(), &[0; N]);
    }

    /// check that a secrete lives, even if its [SecretMemoryPool] is deleted
    #[test]
    fn secret_memory_pool_drop() {
        const N: usize = 0x100;
        let mut pool = SecretMemoryPool::new();
        let secret: ZeroizingSecretBox<[u8; N]> = pool.take();
        std::mem::drop(pool);
        assert_eq!(secret.as_ref(), &[0; N]);
    }

    /// check that a secrete can be reborn, freshly initialized with zero
    #[test]
    fn secret_memory_pool_release() {
        const N: usize = 1;
        let mut pool = SecretMemoryPool::new();
        let mut secret: ZeroizingSecretBox<[u8; N]> = pool.take();
        let old_secret_ptr = secret.as_ref().as_ptr();

        secret.as_mut()[0] = 0x13;
        pool.release(secret);

        // now check that we get the same ptr
        let new_secret: ZeroizingSecretBox<[u8; N]> = pool.take();
        assert_eq!(old_secret_ptr, new_secret.as_ref().as_ptr());

        // and that the secret was zeroized
        assert_eq!(new_secret.as_ref(), &[0; N]);
    }
}
