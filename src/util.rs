use base64::{
    display::Base64Display as B64Display, read::DecoderReader as B64Reader,
    write::EncoderWriter as B64Writer,
};
use std::{
    borrow::{Borrow, BorrowMut},
    cmp::min,
    io::{Read, Write},
    time::{Duration, Instant},
};

#[inline]
pub fn xor_into(a: &mut [u8], b: &[u8]) {
    assert!(a.len() == b.len());
    for (av, bv) in a.iter_mut().zip(b.iter()) {
        *av ^= *bv;
    }
}

// TODO: Zeroize result?
/** Concatenate two byte arrays */
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

pub fn cpy_min<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, to: &mut T) {
    let src = src.borrow();
    let dst = to.borrow_mut();
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

const B64TYPE: base64::Config = base64::STANDARD;

pub fn fmt_b64<'a>(payload: &'a [u8]) -> B64Display<'a> {
    B64Display::<'a>::with_config(payload, B64TYPE)
}

pub fn b64_writer<W: Write>(w: W) -> B64Writer<W> {
    B64Writer::new(w, B64TYPE)
}

pub fn b64_reader<R: Read>(r: &mut R) -> B64Reader<'_, R> {
    B64Reader::new(r, B64TYPE)
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

#[macro_export]
macro_rules! multimatch {
    ($val:expr) => {{ () }};
    ($val:expr, $($p:pat => $thn:expr),*) => {{
        let v = $val;
        ($(if let $p = v { Some($thn) } else { None }),*)
    }};
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
