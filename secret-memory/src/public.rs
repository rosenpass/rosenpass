use crate::debug::debug_crypto_array;
use anyhow::Context;
use rand::{Fill as Randomize, Rng};
use rosenpass_to::{ops::copy_slice, To};
use rosenpass_util::b64::{b64_decode, b64_encode};
use rosenpass_util::file::{
    fopen_r, fopen_w, LoadValue, LoadValueB64, ReadExactToEnd, ReadSliceToEnd, StoreValue,
    StoreValueB64, StoreValueB64Writer, Visibility,
};
use rosenpass_util::functional::mutating;
use std::borrow::{Borrow, BorrowMut};
use std::fmt;
use std::io::Write;
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
        copy_slice(value).to_this(Self::zero)
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

impl<const N: usize> LoadValueB64 for Public<N> {
    type Error = anyhow::Error;

    fn load_b64<const F: usize, P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        let mut f = [0u8; F];
        let mut v = Public::zero();
        let p = path.as_ref();

        let len = fopen_r(p)?
            .read_slice_to_end(&mut f)
            .with_context(|| format!("Could not load file {p:?}"))?;

        b64_decode(&f[0..len], &mut v.value)
            .with_context(|| format!("Could not decode base64 file {p:?}"))?;

        Ok(v)
    }
}

impl<const N: usize> StoreValueB64 for Public<N> {
    type Error = anyhow::Error;

    fn store_b64<const F: usize, P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        let p = path.as_ref();
        let mut f = [0u8; F];
        let encoded_str = b64_encode(&self.value, &mut f)
            .with_context(|| format!("Could not encode base64 file {p:?}"))?;
        fopen_w(p, Visibility::Public)?
            .write_all(encoded_str.as_bytes())
            .with_context(|| format!("Could not write file {p:?}"))?;
        Ok(())
    }
}

impl<const N: usize> StoreValueB64Writer for Public<N> {
    type Error = anyhow::Error;

    fn store_b64_writer<const F: usize, W: std::io::Write>(
        &self,
        mut writer: W,
    ) -> Result<(), Self::Error> {
        let mut f = [0u8; F];
        let encoded_str =
            b64_encode(&self.value, &mut f).with_context(|| "Could not encode secret to base64")?;

        writer
            .write_all(encoded_str.as_bytes())
            .with_context(|| "Could not write base64 to writer")?;
        Ok(())
    }
}

#[derive(Clone, Hash, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct PublicBox<const N: usize> {
    pub inner: Box<Public<N>>,
}

impl<const N: usize> PublicBox<N> {
    /// Create a new [PublicBox] from a byte slice
    pub fn from_slice(value: &[u8]) -> Self {
        Self {
            inner: Box::new(Public::from_slice(value)),
        }
    }

    /// Create a new [PublicBox] from a byte array
    pub fn new(value: [u8; N]) -> Self {
        Self {
            inner: Box::new(Public::new(value)),
        }
    }

    /// Create a zero initialized [PublicBox]
    pub fn zero() -> Self {
        Self {
            inner: Box::new(Public::zero()),
        }
    }

    /// Create a random initialized [PublicBox]
    pub fn random() -> Self {
        Self {
            inner: Box::new(Public::random()),
        }
    }

    /// Randomize all bytes in an existing [PublicBox]
    pub fn randomize(&mut self) {
        self.inner.randomize()
    }
}

impl<const N: usize> Randomize for PublicBox<N> {
    fn try_fill<R: Rng + ?Sized>(&mut self, rng: &mut R) -> Result<(), rand::Error> {
        self.inner.try_fill(rng)
    }
}

impl<const N: usize> fmt::Debug for PublicBox<N> {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        debug_crypto_array(&**self, fmt)
    }
}

impl<const N: usize> Deref for PublicBox<N> {
    type Target = [u8; N];

    fn deref(&self) -> &[u8; N] {
        self.inner.deref()
    }
}

impl<const N: usize> DerefMut for PublicBox<N> {
    fn deref_mut(&mut self) -> &mut [u8; N] {
        self.inner.deref_mut()
    }
}

impl<const N: usize> Borrow<[u8]> for PublicBox<N> {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl<const N: usize> BorrowMut<[u8]> for PublicBox<N> {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.deref_mut()
    }
}

impl<const N: usize> LoadValue for PublicBox<N> {
    type Error = anyhow::Error;

    // This is implemented separately from Public to avoid allocating too much stack memory
    fn load<P: AsRef<Path>>(path: P) -> anyhow::Result<Self> {
        let mut p = Self::random();
        fopen_r(path)?.read_exact_to_end(p.deref_mut())?;
        Ok(p)
    }
}

impl<const N: usize> StoreValue for PublicBox<N> {
    type Error = anyhow::Error;

    fn store<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        self.inner.store(path)
    }
}

impl<const N: usize> LoadValueB64 for PublicBox<N> {
    type Error = anyhow::Error;

    // This is implemented separately from Public to avoid allocating too much stack memory
    fn load_b64<const F: usize, P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized,
    {
        // A vector is used here to ensure heap allocation without copy from stack
        let mut f = vec![0u8; F];
        let mut v = PublicBox::zero();
        let p = path.as_ref();

        let len = fopen_r(p)?
            .read_slice_to_end(&mut f)
            .with_context(|| format!("Could not load file {p:?}"))?;

        b64_decode(&f[0..len], v.deref_mut())
            .with_context(|| format!("Could not decode base64 file {p:?}"))?;

        Ok(v)
    }
}

impl<const N: usize> StoreValueB64 for PublicBox<N> {
    type Error = anyhow::Error;

    fn store_b64<const F: usize, P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        self.inner.store_b64::<F, P>(path)
    }
}

impl<const N: usize> StoreValueB64Writer for PublicBox<N> {
    type Error = anyhow::Error;

    fn store_b64_writer<const F: usize, W: std::io::Write>(
        &self,
        writer: W,
    ) -> Result<(), Self::Error> {
        self.inner.store_b64_writer::<F, W>(writer)
    }
}

#[cfg(test)]
mod tests {

    #[cfg(test)]
    #[allow(clippy::module_inception)]
    mod tests {
        use crate::{Public, PublicBox};
        use rosenpass_util::{
            b64::b64_encode,
            file::{
                fopen_w, LoadValue, LoadValueB64, StoreValue, StoreValueB64, StoreValueB64Writer,
                Visibility,
            },
        };
        use std::{fs, ops::Deref, os::unix::fs::PermissionsExt};
        use tempfile::tempdir;

        /// Number of bytes in payload for load and store tests
        const N: usize = 100;

        /// Convenience function for running a load/store test
        fn run_load_store_test<
            T: LoadValue<Error = anyhow::Error>
                + StoreValue<Error = anyhow::Error>
                + Deref<Target = [u8; N]>,
        >() {
            // Generate original random bytes
            let original_bytes: [u8; N] = [rand::random(); N];

            // Create a temporary directory
            let temp_dir = tempdir().unwrap();

            // Store the original bytes to an example file in the temporary directory
            let example_file = temp_dir.path().join("example_file");
            std::fs::write(&example_file, original_bytes).unwrap();

            // Load the value from the example file into our generic type
            let loaded_public = T::load(&example_file).unwrap();

            // Check that the loaded value matches the original bytes
            assert_eq!(loaded_public.deref(), &original_bytes);

            // Store the loaded value to a different file in the temporary directory
            let new_file = temp_dir.path().join("new_file");
            loaded_public.store(&new_file).unwrap();

            // Read the contents of the new file
            let new_file_contents = fs::read(&new_file).unwrap();

            // Read the contents of the original file
            let original_file_contents = fs::read(&example_file).unwrap();

            // Check that the contents of the new file match the original file
            assert_eq!(new_file_contents, original_file_contents);
        }

        /// Convenience function for running a base64 load/store test
        fn run_base64_load_store_test<
            T: LoadValueB64<Error = anyhow::Error>
                + StoreValueB64<Error = anyhow::Error>
                + StoreValueB64Writer<Error = anyhow::Error>
                + Deref<Target = [u8; N]>,
        >() {
            // Generate original random bytes
            let original_bytes: [u8; N] = [rand::random(); N];
            // Create a temporary directory
            let temp_dir = tempdir().unwrap();
            let example_file = temp_dir.path().join("example_file");
            let mut encoded_public = [0u8; N * 2];
            let encoded_public = b64_encode(&original_bytes, &mut encoded_public).unwrap();
            std::fs::write(&example_file, encoded_public).unwrap();

            // Load the public from the example file
            let loaded_public = T::load_b64::<{ N * 2 }, _>(&example_file).unwrap();
            // Check that the loaded public matches the original bytes
            assert_eq!(loaded_public.deref(), &original_bytes);

            // Store the loaded public to a different file in the temporary directory
            let new_file = temp_dir.path().join("new_file");
            loaded_public.store_b64::<{ N * 2 }, _>(&new_file).unwrap();

            // Read the contents of the new file
            let new_file_contents = fs::read(&new_file).unwrap();
            // Read the contents of the original file
            let original_file_contents = fs::read(&example_file).unwrap();
            // Check that the contents of the new file match the original file
            assert_eq!(new_file_contents, original_file_contents);

            // Check new file permissions are public
            let metadata = fs::metadata(&new_file).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o000777, 0o644);

            // Store the loaded public to a different file in the temporary directory for a second time
            let new_file = temp_dir.path().join("new_file_writer");
            let new_file_writer = fopen_w(new_file.clone(), Visibility::Public).unwrap();
            loaded_public
                .store_b64_writer::<{ N * 2 }, _>(&new_file_writer)
                .unwrap();

            // Read the contents of the new file
            let new_file_contents = fs::read(&new_file).unwrap();
            // Read the contents of the original file
            let original_file_contents = fs::read(&example_file).unwrap();
            // Check that the contents of the new file match the original file
            assert_eq!(new_file_contents, original_file_contents);

            // Check new file permissions are public
            let metadata = fs::metadata(&new_file).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o000777, 0o644);
        }

        /// Test loading a [Public] from an example file, and then storing it again in a new file
        #[test]
        fn test_public_load_store() {
            run_load_store_test::<Public<N>>();
        }

        /// Test loading a [PublicBox] from an example file, and then storing it again in a new file
        #[test]
        fn test_public_box_load_store() {
            run_load_store_test::<PublicBox<N>>();
        }

        /// Test loading a base64-encoded [Public] from an example file, and then storing it again
        /// in a different file
        #[test]
        fn test_public_load_store_base64() {
            run_base64_load_store_test::<Public<N>>();
        }

        /// Test loading a base64-encoded [PublicBox] from an example file, and then storing it
        /// again in a different file
        #[test]
        fn test_public_box_load_store_base64() {
            run_base64_load_store_test::<PublicBox<N>>();
        }
    }
}
