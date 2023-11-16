//! Helper functions and macros
use anyhow::{ensure, Context, Result};
use std::{
    fs::{File, OpenOptions},
    io::Read,
    path::Path,
};

use crate::coloring::{Public, Secret};
use rosenpass_util::b64::b64_reader;

/// load'n store

/// Open a file writable
pub fn fopen_w<P: AsRef<Path>>(path: P) -> Result<File> {
    Ok(OpenOptions::new()
        .read(false)
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?)
}
/// Open a file readable
pub fn fopen_r<P: AsRef<Path>>(path: P) -> Result<File> {
    Ok(OpenOptions::new()
        .read(true)
        .write(false)
        .create(false)
        .truncate(false)
        .open(path)?)
}

pub trait ReadExactToEnd {
    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<()>;
}

impl<R: Read> ReadExactToEnd for R {
    fn read_exact_to_end(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut dummy = [0u8; 8];
        self.read_exact(buf)?;
        ensure!(self.read(&mut dummy)? == 0, "File too long!");
        Ok(())
    }
}

pub trait LoadValue {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;
}

pub trait LoadValueB64 {
    fn load_b64<P: AsRef<Path>>(path: P) -> Result<Self>
    where
        Self: Sized;
}

trait StoreValue {
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<()>;
}

trait StoreSecret {
    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<()>;
}

impl<T: StoreValue> StoreSecret for T {
    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        self.store(path)
    }
}

impl<const N: usize> LoadValue for Secret<N> {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut v = Self::random();
        let p = path.as_ref();
        fopen_r(p)?
            .read_exact_to_end(v.secret_mut())
            .with_context(|| format!("Could not load file {p:?}"))?;
        Ok(v)
    }
}

impl<const N: usize> LoadValueB64 for Secret<N> {
    fn load_b64<P: AsRef<Path>>(path: P) -> Result<Self> {
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
    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        std::fs::write(path, self.secret())?;
        Ok(())
    }
}

impl<const N: usize> LoadValue for Public<N> {
    fn load<P: AsRef<Path>>(path: P) -> Result<Self> {
        let mut v = Self::random();
        fopen_r(path)?.read_exact_to_end(&mut *v)?;
        Ok(v)
    }
}

impl<const N: usize> StoreValue for Public<N> {
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        std::fs::write(path, **self)?;
        Ok(())
    }
}
