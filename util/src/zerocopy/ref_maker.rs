use std::marker::PhantomData;

use anyhow::{ensure, Context};
use zerocopy::{ByteSlice, ByteSliceMut, Ref};
use zeroize::Zeroize;

use crate::zeroize::ZeroizedExt;

#[derive(Clone, Copy, Debug)]
/// A convenience type for working with mutable references to a buffer and an
/// expected target type.
pub struct RefMaker<B: Sized, T> {
    buf: B,
    _phantom_t: PhantomData<T>,
}

impl<B, T> RefMaker<B, T> {
    /// Creates a new RefMaker with the given buffer
    pub fn new(buf: B) -> Self {
        let _phantom_t = PhantomData;
        Self { buf, _phantom_t }
    }

    /// Returns the size in bytes needed for target type T
    pub const fn target_size() -> usize {
        std::mem::size_of::<T>()
    }

    /// Consumes this RefMaker and returns the inner buffer
    pub fn into_buf(self) -> B {
        self.buf
    }

    /// Returns a reference to the inner buffer
    pub fn buf(&self) -> &B {
        &self.buf
    }

    /// Returns a mutable reference to the inner buffer
    pub fn buf_mut(&mut self) -> &mut B {
        &mut self.buf
    }
}

impl<B: ByteSlice, T> RefMaker<B, T> {
    /// Parses the buffer into a reference of type T
    pub fn parse(self) -> anyhow::Result<Ref<B, T>> {
        self.ensure_fit()?;
        Ref::<B, T>::new(self.buf).context("Parser error!")
    }

    /// Splits the buffer into a RefMaker containing the first `target_size` bytes and the remaining tail
    pub fn from_prefix_with_tail(self) -> anyhow::Result<(Self, B)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), tail))
    }

    /// Splits the buffer into two RefMakers, with the first containing the first `target_size` bytes
    pub fn split_prefix(self) -> anyhow::Result<(Self, Self)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), Self::new(tail)))
    }

    /// Returns a RefMaker containing only the first `target_size` bytes
    pub fn from_prefix(self) -> anyhow::Result<Self> {
        Ok(Self::from_prefix_with_tail(self)?.0)
    }

    /// Splits the buffer into a RefMaker containing the last `target_size` bytes and the preceding head
    pub fn from_suffix_with_head(self) -> anyhow::Result<(Self, B)> {
        self.ensure_fit()?;
        let point = self.bytes().len() - Self::target_size();
        let (head, tail) = self.buf.split_at(point);
        Ok((Self::new(tail), head))
    }

    /// Splits the buffer into two RefMakers, with the second containing the last `target_size` bytes
    pub fn split_suffix(self) -> anyhow::Result<(Self, Self)> {
        self.ensure_fit()?;
        let point = self.bytes().len() - Self::target_size();
        let (head, tail) = self.buf.split_at(point);
        Ok((Self::new(head), Self::new(tail)))
    }

    /// Returns a RefMaker containing only the last `target_size` bytes
    pub fn from_suffix(self) -> anyhow::Result<Self> {
        Ok(Self::from_suffix_with_head(self)?.0)
    }

    /// Returns a reference to the underlying bytes
    pub fn bytes(&self) -> &[u8] {
        self.buf().deref()
    }

    /// Ensures the buffer is large enough to hold type T
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
    /// Creates a zeroed reference of type T from the buffer
    pub fn make_zeroized(self) -> anyhow::Result<Ref<B, T>> {
        self.zeroized().parse()
    }

    /// Returns a mutable reference to the underlying bytes
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.buf_mut().deref_mut()
    }
}

impl<B: ByteSliceMut, T> Zeroize for RefMaker<B, T> {
    fn zeroize(&mut self) {
        self.bytes_mut().zeroize()
    }
}
