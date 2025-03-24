//! Helpers for working with files

use anyhow::ensure;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::{fs::OpenOptions, path::Path};
use rosenpass_to::{with_destination, To};

/// Level of secrecy applied for a file
pub enum Visibility {
    /// The file might contain a public key
    Public,
    /// The file might contain a secret key
    Secret,
}

/// Open a file writeably, truncating the file.
///
/// Sensible default permissions are chosen based on the value of `visibility`
///
/// # Examples
///
/// ```
/// use std::io::{Write, Read};
/// use tempfile::tempdir;
/// use rosenpass_util::file::{fopen_r, fopen_w, Visibility};
///
/// const CONTENTS : &[u8] = b"Hello World";
///
/// let dir = tempdir()?;
/// let path = dir.path().join("secret_key");
///
/// let mut f = fopen_w(&path, Visibility::Secret)?;
/// f.write_all(CONTENTS)?;
///
/// let mut f = fopen_r(&path)?;
/// let mut b = Vec::new();
/// f.read_to_end(&mut b)?;
/// assert_eq!(CONTENTS, &b);
///
/// Ok::<(), std::io::Error>(())
/// ```
pub fn fopen_w<P: AsRef<Path>>(path: P, visibility: Visibility) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).read(false).truncate(true);
    match visibility {
        Visibility::Public => options.mode(0o644),
        Visibility::Secret => options.mode(0o600),
    };
    options.open(path)
}

/// Open a file readably
///
/// # Examples
///
/// See [fopen_w].
pub fn fopen_r<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)
}

/// Trait for reading data from a file into a slice
pub trait ReadSliceToEnd: Read {
    /// Read as much data from the file as will fit in `buf`.
    ///
    /// Returns the number of bytes written.
    /// If the file contains more data than fit in the buffer, an error is returned.
    /// 
    /// # Examples
    ///
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::file::ReadSliceToEnd;
    /// # let DATA = b"Hello World";
    /// # let mut file = Cursor::new(DATA);
    /// let mut buf = [0u8; 11];
    /// let res = Clone::clone(&DATA).read_slice_to_end().to(&mut buf);
    /// assert_eq!(res.unwrap(), 11);
    /// assert_eq!(&buf, b"Hello World");
    /// ```
    fn read_slice_to_end(&mut self) -> impl To<[u8], anyhow::Result<usize>>;
}

impl<T: Read> ReadSliceToEnd for T {
    fn read_slice_to_end(&mut self) -> impl To<[u8], anyhow::Result<usize>> {
        with_destination(move |buf: &mut [u8]| {
            let mut read = 0;
            loop {
                let bytes_read = self.read(&mut buf[read..])?;
                if bytes_read == 0 {
                    break;
                }
                read += bytes_read;
                if read == buf.len() {
                    break;
                }
            }
            let mut dummy = [0u8; 1];
            ensure!(self.read(&mut dummy)? == 0, "File too long!");
            Ok(read)
        })
    }
}

/// Trait for reading data from a file into a slice
pub trait ReadExactToEnd: Read {
    /// Read exactly as much data from the file as will fit in `buf`.
    ///
    /// If the file contains more data or less data than fit in the buffer, an error is returned.
    /// 
    /// # Examples
    ///
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::file::ReadExactToEnd;
    /// # let DATA = b"Hello World";
    /// # let mut file = Cursor::new(DATA);
    /// let mut buf = [0u8; 11];
    /// let res = Clone::clone(&DATA).read_exact_to_end().to(&mut buf);
    /// assert!(res.is_ok());
    /// assert_eq!(&buf, b"Hello World");
    /// ```
    fn read_exact_to_end(&mut self) -> impl To<[u8], anyhow::Result<()>>;
}

impl<T: Read> ReadExactToEnd for T {
    fn read_exact_to_end(&mut self) -> impl To<[u8], anyhow::Result<()>> {
        with_destination(move |buf: &mut [u8]| {
            self.read_exact(buf)?;
            let mut dummy = [0u8; 1];
            ensure!(self.read(&mut dummy)? == 0, "File too long!");
            Ok(())
        })
    }
}

/// Load a value from a file
pub trait LoadValue {
    /// Error type returned
    type Error;

    /// Load a value from a file
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::Path;
    /// use std::io::Write;
    /// use tempfile::tempdir;
    /// use rosenpass_util::file::{fopen_r, fopen_w, LoadValue, ReadExactToEnd, StoreValue, Visibility};
    ///
    /// #[derive(Debug, PartialEq, Eq)]
    /// struct MyInt(pub u32);
    ///
    /// impl StoreValue for MyInt {
    ///     type Error = std::io::Error;
    ///
    ///     fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
    ///         let mut f = fopen_w(path, Visibility::Public)?;
    ///         f.write_all(&self.0.to_le_bytes())
    ///     }
    /// }
    ///
    /// impl LoadValue for MyInt {
    ///     type Error = anyhow::Error;
    ///
    ///     fn load<P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    ///     where
    ///         Self: Sized,
    ///     {
    ///         let mut b = [0u8; 4];
    ///         fopen_r(path)?.read_exact_to_end(&mut b)?;
    ///         Ok(MyInt(u32::from_le_bytes(b)))
    ///     }
    /// }
    ///
    /// let dir = tempdir()?;
    /// let path = dir.path().join("my_int");
    ///
    /// let orig = MyInt(17);
    /// orig.store(&path)?;
    ///
    /// let copy = MyInt::load(&path)?;
    /// assert_eq!(orig, copy);
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    fn load<P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Load a value from a file encoded as base64
pub trait LoadValueB64 {
    /// Error type returned
    type Error;

    /// Load a value from a file encoded as base64
    ///
    /// # Examples
    ///
    /// ```
    /// use std::path::Path;
    /// use tempfile::tempdir;
    /// use rosenpass_util::b64::{b64_decode, b64_encode};
    /// use rosenpass_util::file::{
    ///     fopen_r, fopen_w, LoadValueB64, ReadSliceToEnd, StoreValueB64, StoreValueB64Writer,
    ///     Visibility,
    /// };
    ///
    /// #[derive(Debug, PartialEq, Eq)]
    /// struct MyInt(pub u32);
    ///
    /// impl StoreValueB64Writer for MyInt {
    ///     type Error = anyhow::Error;
    ///
    ///     fn store_b64_writer<const F: usize, W: std::io::Write>(
    ///         &self,
    ///         mut writer: W,
    ///     ) -> Result<(), Self::Error> {
    ///         // Let me just point out while writing this example,
    ///         // that this API is currently, entirely shit in terms of
    ///         // how it deals with buffer lengths.
    ///         let mut buf = [0u8; F];
    ///         let b64 = b64_encode(&self.0.to_le_bytes(), &mut buf)?;
    ///         writer.write_all(b64.as_bytes())?;
    ///         Ok(())
    ///     }
    /// }
    ///
    /// impl StoreValueB64 for MyInt {
    ///     type Error = anyhow::Error;
    ///
    ///     fn store_b64<const F: usize, P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>
    ///     where
    ///         Self: Sized,
    ///     {
    ///         // The buffer length (first generic arg) is kind of an upper bound
    ///         self.store_b64_writer::<F, _>(fopen_w(path, Visibility::Public)?)
    ///     }
    /// }
    ///
    /// impl LoadValueB64 for MyInt {
    ///     type Error = anyhow::Error;
    ///
    ///     fn load_b64<const F: usize, P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    ///     where
    ///         Self: Sized,
    ///     {
    ///         // The buffer length is kind of an upper bound
    ///         let mut b64_buf = [0u8; F];
    ///         let b64_len = fopen_r(path)?.read_slice_to_end(&mut b64_buf)?;
    ///         let b64_dat = &b64_buf[..b64_len];
    ///
    ///         let mut buf = [0u8; 4];
    ///         b64_decode(b64_dat, &mut buf)?;
    ///         Ok(MyInt(u32::from_le_bytes(buf)))
    ///     }
    /// }
    ///
    /// let dir = tempdir()?;
    /// let path = dir.path().join("my_int");
    ///
    /// let orig = MyInt(17);
    /// orig.store_b64::<10, _>(&path)?;
    ///
    /// let copy = MyInt::load_b64::<10, _>(&path)?;
    /// assert_eq!(orig, copy);
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    fn load_b64<const F: usize, P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

/// Store a value encoded as base64 in a file.
pub trait StoreValueB64 {
    /// Error type returned
    type Error;

    /// Store a value encoded as base64 in a file.
    ///
    /// # Examples
    ///
    /// See [LoadValueB64::load_b64].
    fn store_b64<const F: usize, P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>
    where
        Self: Sized;
}

/// Store a value encoded as base64 to a writable stream
pub trait StoreValueB64Writer {
    /// Error type returned
    type Error;

    /// Store a value encoded as base64 to a writable stream
    ///
    /// # Examples
    ///
    /// See [LoadValueB64::load_b64].
    fn store_b64_writer<const F: usize, W: std::io::Write>(
        &self,
        writer: W,
    ) -> Result<(), Self::Error>;
}

/// Store a value in a file
pub trait StoreValue {
    /// Error type returned
    type Error;

    /// Store a value in a file
    ///
    /// # Examples
    ///
    /// See [LoadValue::load].
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn test_fopen_w_public() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = fopen_w(path, Visibility::Public).unwrap();
        file.write_all(b"test").unwrap();
        let metadata = file.metadata().unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode(), 0o100644);
    }

    #[test]
    fn test_fopen_w_secret() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = fopen_w(path, Visibility::Secret).unwrap();
        file.write_all(b"test").unwrap();
        let metadata = file.metadata().unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode(), 0o100600);
    }

    #[test]
    fn test_fopen_r() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = File::create(path.clone()).unwrap();
        file.write_all(b"test").unwrap();
        let mut contents = String::new();
        let mut file = fopen_r(path).unwrap();
        file.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "test");
    }

    #[test]
    fn test_read_slice_to_end() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = File::create(path.clone()).unwrap();
        file.write_all(b"test").unwrap();
        let mut buf = [0u8; 4];
        let mut file = fopen_r(path).unwrap();
        file.read_slice_to_end().to(&mut buf).unwrap();
        assert_eq!(buf, [116, 101, 115, 116]);
    }

    #[test]
    fn test_read_exact_to_end() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = File::create(path.clone()).unwrap();
        file.write_all(b"test").unwrap();
        let mut buf = [0u8; 4];
        let mut file = fopen_r(path).unwrap();
        file.read_exact_to_end().to(&mut buf).unwrap();
        assert_eq!(buf, [116, 101, 115, 116]);
    }

    #[test]
    fn test_read_exact_to_end_to_long() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = File::create(path.clone()).unwrap();
        file.write_all(b"test").unwrap();
        let mut buf = [0u8; 3];
        let mut file = fopen_r(path).unwrap();
        let result = file.read_exact_to_end().to(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "File too long!");
    }

    #[test]
    fn test_read_slice_to_end_to_long() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = File::create(path.clone()).unwrap();
        file.write_all(b"test").unwrap();
        let mut buf = [0u8; 3];
        let mut file = fopen_r(path).unwrap();
        let result = file.read_slice_to_end().to(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "File too long!");
    }
}
