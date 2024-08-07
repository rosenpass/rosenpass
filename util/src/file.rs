use anyhow::ensure;
use std::fs::File;
use std::io::Read;
use std::os::unix::fs::OpenOptionsExt;
use std::{fs::OpenOptions, path::Path};

pub enum Visibility {
    Public,
    Secret,
}

/// Open a file writable
pub fn fopen_w<P: AsRef<Path>>(path: P, visibility: Visibility) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.create(true).write(true).read(false).truncate(true);
    match visibility {
        Visibility::Public => options.mode(0o644),
        Visibility::Secret => options.mode(0o600),
    };
    options.open(path)
}
/// Open a file readable
pub fn fopen_r<P: AsRef<Path>>(path: P) -> std::io::Result<File> {
    OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)
}

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

pub trait DisplayValueB64 {
    type Error;

    fn display_b64<'o>(&self, output: &'o mut [u8]) -> Result<&'o str, Self::Error>;
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
        file.read_slice_to_end(&mut buf).unwrap();
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
        file.read_exact_to_end(&mut buf).unwrap();
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
        let result = file.read_exact_to_end(&mut buf);
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
        let result = file.read_slice_to_end(&mut buf);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "File too long!");
    }
}
