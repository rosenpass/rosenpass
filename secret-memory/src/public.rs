use crate::debug::debug_crypto_array;
use rand::{Fill as Randomize, Rng};
use rosenpass_to::{ops::copy_slice, To};
use rosenpass_util::file::{fopen_r, LoadValue, ReadExactToEnd, StoreValue};
use rosenpass_util::functional::mutating;
use std::borrow::{Borrow, BorrowMut};
use std::fmt;
use std::ops::{Deref, DerefMut};
use std::path::Path;

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
        copy_slice(value).to_this(|| Self::zero())
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
        self.try_fill(&mut crate::rand::rng()).unwrap()
    }
}

impl<const N: usize> Randomize for Public<N> {
    fn try_fill<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Result<(), rand::Error> {
        self.value.try_fill(rng)
    }
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

impl<const N: usize> Borrow<[u8; N]> for Public<N> {
    fn borrow(&self) -> &[u8; N] {
        &self.value
    }
}
impl<const N: usize> BorrowMut<[u8; N]> for Public<N> {
    fn borrow_mut(&mut self) -> &mut [u8; N] {
        &mut self.value
    }
}

impl<const N: usize> Borrow<[u8]> for Public<N> {
    fn borrow(&self) -> &[u8] {
        &self.value
    }
}
impl<const N: usize> BorrowMut<[u8]> for Public<N> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        &mut self.value
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
