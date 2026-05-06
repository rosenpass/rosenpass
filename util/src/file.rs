//! Helpers for working with files

use anyhow::ensure;
use std::fs::File;
use std::io::Read;

#[cfg(unix)]
use std::os::unix::fs::OpenOptionsExt;

use std::{fs::OpenOptions, path::Path};

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
pub fn fopen_w<P: AsRef<Path>>(path: P, visibility: Visibility) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).read(false).truncate(true);
    
    #[cfg(unix)]
    match visibility {
        Visibility::Public => options.mode(0o644),
        Visibility::Secret => options.mode(0o600),
    };

    #[cfg(windows)]
    let _ = visibility; // Keeps the variable used to avoid warnings

    options.open(path)
}

/// Open a file readably
pub fn fopen_r<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)
}

/// Extension trait for [std::io::Read] adding [read_slice_to_end]
pub trait ReadSliceToEnd {
    type Error;
    fn read_slice_to_end(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error>;
}

impl<R: Read> ReadSliceToEnd for R {
    type Error = anyhow::Error;

    fn read_slice_to_end(&mut self, buf: &mut [u8]) -> anyhow::Result<usize> {
        let mut dummy = [0u8; 8];
        let mut read = 0;
        while read < buf.len() {
            let bytes_read = self.read(&mut buf[read..])?;
            if bytes_read == 0 {
                break;
            }
            read += bytes_read;
        }
        ensure!(self.read(&mut dummy)? == 0, "File too long!");
        Ok(read)
    }
}

/// Extension trait for [std::io::Read] adding [read_exact_to_end]
pub trait ReadExactToEnd {
    type Error;
    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<(), Self::Error>;
}

impl<R: Read> ReadExactToEnd for R {
    type Error = anyhow::Error;

    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        let mut dummy = [0u8; 8];
        self.read_exact(buf)?;
        ensure!(self.read(&mut dummy)? == 0, "File too long!");
        Ok(())
    }
}

pub trait LoadValue {
    type Error;
    fn load<P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait LoadValueB64 {
    type Error;
    fn load_b64<const F: usize, P: AsRef<Path>>(path: P) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait StoreValueB64 {
    type Error;
    fn store_b64<const F: usize, P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>
    where
        Self: Sized;
}

pub trait StoreValueB64Writer {
    type Error;
    fn store_b64_writer<const F: usize, W: std::io::Write>(
        &self,
        writer: W,
    ) -> Result<(), Self::Error>;
}

pub trait StoreValue {
    type Error;
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::tempdir;

    #[test]
    fn test_fopen_w_public() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = fopen_w(path, Visibility::Public).unwrap();
        file.write_all(b"test").unwrap();
    }

    #[test]
    fn test_fopen_w_secret() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let mut file = fopen_w(path, Visibility::Secret).unwrap();
        file.write_all(b"test").unwrap();
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
}
