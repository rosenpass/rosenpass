use std::marker::PhantomData;

use anyhow::{ensure, Context};
use zerocopy::{ByteSlice, ByteSliceMut, Ref};
use zeroize::Zeroize;

use crate::zeroize::ZeroizedExt;

#[derive(Clone, Copy, Debug)]
pub struct RefMaker<B: Sized, T> {
    buf: B,
    _phantom_t: PhantomData<T>,
}

impl<B, T> RefMaker<B, T> {
    pub fn new(buf: B) -> Self {
        let _phantom_t = PhantomData;
        Self { buf, _phantom_t }
    }

    pub const fn target_size() -> usize {
        std::mem::size_of::<T>()
    }

    pub fn into_buf(self) -> B {
        self.buf
    }

    pub fn buf(&self) -> &B {
        &self.buf
    }

    pub fn buf_mut(&mut self) -> &mut B {
        &mut self.buf
    }
}

impl<B: ByteSlice, T> RefMaker<B, T> {
    pub fn parse(self) -> anyhow::Result<Ref<B, T>> {
        self.ensure_fit()?;
        Ref::<B, T>::new(self.buf).context("Parser error!")
    }

    pub fn from_prefix_with_tail(self) -> anyhow::Result<(Self, B)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), tail))
    }

    pub fn split_prefix(self) -> anyhow::Result<(Self, Self)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), Self::new(tail)))
    }

    pub fn from_prefix(self) -> anyhow::Result<Self> {
        Ok(Self::from_prefix_with_tail(self)?.0)
    }

    pub fn from_suffix_with_tail(self) -> anyhow::Result<(Self, B)> {
        self.ensure_fit()?;
        let point = self.bytes().len() - Self::target_size();
        let (head, tail) = self.buf.split_at(point);
        Ok((Self::new(head), tail))
    }

    pub fn split_suffix(self) -> anyhow::Result<(Self, Self)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), Self::new(tail)))
    }

    pub fn from_suffix(self) -> anyhow::Result<Self> {
        Ok(Self::from_suffix_with_tail(self)?.0)
    }

    pub fn bytes(&self) -> &[u8] {
        self.buf().deref()
    }

    pub fn ensure_fit(&self) -> anyhow::Result<()> {
        let have = self.bytes().len();
        let need = Self::target_size();
        ensure!(
            need <= have,
            "Buffer is undersized at {have} bytes (need {need} bytes)!"
        );
        Ok(())
    }
}

impl<B: ByteSliceMut, T> RefMaker<B, T> {
    pub fn make_zeroized(self) -> anyhow::Result<Ref<B, T>> {
        self.zeroized().parse()
    }

    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.buf_mut().deref_mut()
    }
}

impl<B: ByteSliceMut, T> Zeroize for RefMaker<B, T> {
    fn zeroize(&mut self) {
        self.bytes_mut().zeroize()
    }
}
