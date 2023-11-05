//! Helper functions and macros
use anyhow::{ensure, Context, Result};
use base64::{
    display::Base64Display as B64Display, read::DecoderReader as B64Reader,
    write::EncoderWriter as B64Writer,
};
use std::{
    borrow::{Borrow, BorrowMut},
    cmp::min,
    fs::{File, OpenOptions},
    io::{Read, Write},
    path::Path,
    time::{Duration, Instant},
};

// TODO: Move everything except module declarations out of this file
mod types;
mod math;

use crate::coloring::{Public, Secret};

#[inline]
pub fn xor_into(a: &mut [u8], b: &[u8]) {
    assert!(a.len() == b.len());
    for (av, bv) in a.iter_mut().zip(b.iter()) {
        *av ^= *bv;
    }
}

/// Concatenate two byte arrays
// TODO: Zeroize result?
#[macro_export]
macro_rules! cat {
    ($len:expr; $($toks:expr),+) => {{
        let mut buf = [0u8; $len];
        let mut off = 0;
        $({
            let tok = $toks;
            let tr = ::std::borrow::Borrow::<[u8]>::borrow(tok);
            (&mut buf[off..(off + tr.len())]).copy_from_slice(tr);
            off += tr.len();
        })+
        assert!(off == buf.len(), "Size mismatch in cat!()");
        buf
    }}
}

// TODO: consistent inout ordering
pub fn cpy<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, dst: &mut T) {
    dst.borrow_mut().copy_from_slice(src.borrow());
}

/// Copy from `src` to `dst`. If `src` and `dst` are not of equal length, copy as many bytes as possible.
pub fn cpy_min<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, dst: &mut T) {
    let src = src.borrow();
    let dst = dst.borrow_mut();
    let len = min(src.len(), dst.len());
    dst[..len].copy_from_slice(&src[..len]);
}

/// Try block basically…returns a result and allows the use of the question mark operator inside
#[macro_export]
macro_rules! attempt {
    ($block:expr) => {
        (|| -> ::anyhow::Result<_> { $block })()
    };
}

use base64::engine::general_purpose::GeneralPurpose as Base64Engine;
const B64ENGINE: Base64Engine = base64::engine::general_purpose::STANDARD;

pub fn fmt_b64<'a>(payload: &'a [u8]) -> B64Display<'a, 'static, Base64Engine> {
    B64Display::<'a, 'static>::new(payload, &B64ENGINE)
}

pub fn b64_writer<W: Write>(w: W) -> B64Writer<'static, Base64Engine, W> {
    B64Writer::new(w, &B64ENGINE)
}

pub fn b64_reader<R: Read>(r: R) -> B64Reader<'static, Base64Engine, R> {
    B64Reader::new(r, &B64ENGINE)
}

// TODO remove this once std::cmp::max becomes const
pub const fn max_usize(a: usize, b: usize) -> usize {
    if a > b {
        a
    } else {
        b
    }
}

#[derive(Clone, Debug)]
pub struct Timebase(Instant);

impl Default for Timebase {
    fn default() -> Self {
        Self(Instant::now())
    }
}

impl Timebase {
    pub fn now(&self) -> f64 {
        self.0.elapsed().as_secs_f64()
    }

    pub fn dur(&self, t: f64) -> Duration {
        Duration::from_secs_f64(t)
    }
}

pub fn mutating<T, F>(mut v: T, f: F) -> T
where
    F: Fn(&mut T),
{
    f(&mut v);
    v
}

pub fn sideeffect<T, F>(v: T, f: F) -> T
where
    F: Fn(&T),
{
    f(&v);
    v
}

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
