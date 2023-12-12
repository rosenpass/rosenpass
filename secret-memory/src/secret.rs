use crate::{file::StoreSecret, allocator};
use allocator::{Alloc as SodiumAlloc, Box as SodiumBox, Vec as SodiumVec};
use anyhow::Context;
use lazy_static::lazy_static;
use rand::{Fill as Randomize, Rng};
use rosenpass_util::{
    b64::b64_reader,
    file::{fopen_r, LoadValue, LoadValueB64, ReadExactToEnd},
    functional::mutating,
};
use std::{collections::HashMap, convert::TryInto, fmt, path::Path, sync::Mutex};
use zeroize::{Zeroize, ZeroizeOnDrop};

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
struct SecretMemoryPool {
    pool: HashMap<usize, Vec<SodiumBox<[u8]>>>,
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
    pub fn release<const N: usize>(&mut self, mut sec: SodiumBox<[u8; N]>) {
        sec.zeroize();

        // This conversion sequence is weird but at least it guarantees
        // that the heap allocation is preserved according to the docs
        let sec: SodiumVec<u8> = sec.into();
        let sec: SodiumBox<[u8]> = sec.into();

        self.pool.entry(N).or_default().push(sec);
    }

    /// Take protected memory from the pool, allocating new one if no suitable
    /// chunk is found in the inventory.
    ///
    /// The secret is guaranteed to be full of nullbytes
    pub fn take<const N: usize>(&mut self) -> SodiumBox<[u8; N]> {
        let entry = self.pool.entry(N).or_default();
        match entry.pop() {
            None => SodiumBox::new_in([0u8; N], SodiumAlloc::default()),
            Some(sec) => sec.try_into().unwrap(),
        }
    }
}

/// Storeage for a secret backed by [rosenpass_sodium::alloc::Alloc]
pub struct Secret<const N: usize> {
    storage: Option<SodiumBox<[u8; N]>>,
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
        Self {
            storage: Some(SECRET_CACHE.lock().unwrap().take()),
        }
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

impl<const N: usize> ZeroizeOnDrop for Secret<N> {}
impl<const N: usize> Zeroize for Secret<N> {
    fn zeroize(&mut self) {
        self.secret_mut().zeroize();
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

impl<const N: usize> Drop for Secret<N> {
    fn drop(&mut self) {
        self.storage
            .take()
            .map(|sec| SECRET_CACHE.lock().unwrap().release(sec));
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
        std::fs::write(path, self.secret())?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// check that we can alloc using the magic pool
    #[test]
    fn secret_memory_pool_take() {
        rosenpass_sodium::init().unwrap();
        const N: usize = 0x100;
        let mut pool = SecretMemoryPool::new();
        let secret: SodiumBox<[u8; N]> = pool.take();
        assert_eq!(secret.as_ref(), &[0; N]);
    }

    /// check that a secrete lives, even if its [SecretMemoryPool] is deleted
    #[test]
    fn secret_memory_pool_drop() {
        rosenpass_sodium::init().unwrap();
        const N: usize = 0x100;
        let mut pool = SecretMemoryPool::new();
        let secret: SodiumBox<[u8; N]> = pool.take();
        std::mem::drop(pool);
        assert_eq!(secret.as_ref(), &[0; N]);
    }

    /// check that a secrete can be reborn, freshly initialized with zero
    #[test]
    fn secret_memory_pool_release() {
        rosenpass_sodium::init().unwrap();
        const N: usize = 1;
        let mut pool = SecretMemoryPool::new();
        let mut secret: SodiumBox<[u8; N]> = pool.take();
        let old_secret_ptr = secret.as_ref().as_ptr();

        secret.as_mut()[0] = 0x13;
        pool.release(secret);

        // now check that we get the same ptr
        let new_secret: SodiumBox<[u8; N]> = pool.take();
        assert_eq!(old_secret_ptr, new_secret.as_ref().as_ptr());

        // and that the secret was zeroized
        assert_eq!(new_secret.as_ref(), &[0; N]);
    }
}
