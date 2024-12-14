//! A module providing the [`RefMaker`] type and its associated methods for constructing
//! [`zerocopy::Ref`] references from byte buffers.

use anyhow::{ensure, Context};
use std::marker::PhantomData;
use zerocopy::{ByteSlice, ByteSliceMut, Ref};
use zeroize::Zeroize;

use crate::zeroize::ZeroizedExt;

/// A convenience type for working with buffers and extracting [`zerocopy::Ref`]
/// references.
///
/// `RefMaker` holds a buffer and a target type parameter `T`. Using `RefMaker`,
/// you can validate that the provided buffer is large enough for `T` and then
/// parse out a strongly-typed reference (`Ref`) to that data. It also provides
/// methods for extracting prefixes and suffixes from the buffer.
///
/// # Example
///
/// ```
/// # use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};///
/// # use rosenpass_util::zerocopy::RefMaker;
///
/// #[derive(FromBytes, FromZeroes, AsBytes)]
/// #[repr(C)]
/// struct Header {
///     field1: u32,
///     field2: u16,
///     field3: u16,
/// }
/// #[repr(align(4))]
/// struct AlignedBuf([u8; 8]);
/// let bytes = AlignedBuf([0xAA, 0xBB, 0xCC, 0xDD,
/// 0x00, 0x10, 0x20, 0x30]);
/// let rm = RefMaker::<&[u8], Header>::new(&bytes.0);
/// let header_ref: Ref<&[u8], Header> = rm.parse().unwrap();
/// assert_eq!(header_ref.field1, 0xDDCCBBAA);
/// assert_eq!(header_ref.field2, 0x1000);
/// assert_eq!(header_ref.field3, 0x3020);
/// ```
#[derive(Clone, Copy, Debug)]
pub struct RefMaker<B: Sized, T> {
    buf: B,
    _phantom_t: PhantomData<T>,
}

impl<B, T> RefMaker<B, T> {
    /// Creates a new `RefMaker` with the given buffer.
    ///
    /// # Example
    ///
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let buffer = [0u8; 10];
    /// let rm: RefMaker<_, u32> = RefMaker::new(buffer);
    /// ```
    pub fn new(buf: B) -> Self {
        let _phantom_t = PhantomData;
        Self { buf, _phantom_t }
    }

    /// Returns the size in bytes required by the target type `T`.
    /// This is currently defined as [std::mem::size_of] of `T`.
    pub const fn target_size() -> usize {
        std::mem::size_of::<T>()
    }

    /// Consumes this `RefMaker` and returns the inner buffer.
    pub fn into_buf(self) -> B {
        self.buf
    }

    /// Returns a reference to the inner buffer.
    pub fn buf(&self) -> &B {
        &self.buf
    }

    /// Returns a mutable reference to the inner buffer.
    pub fn buf_mut(&mut self) -> &mut B {
        &mut self.buf
    }
}

impl<B: ByteSlice, T> RefMaker<B, T> {
    /// Parses the buffer into a [`zerocopy::Ref<B, T>`].
    ///
    /// This will fail if the buffer is smaller than `size_of::<T>`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized or if parsing fails.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};
    /// # use rosenpass_util::zerocopy::RefMaker;
    ///
    /// #[derive(FromBytes, FromZeroes, AsBytes, Debug)]
    /// #[repr(C)]
    /// struct Data(u32);
    ///
    /// let bytes: &[u8] = &[0x01, 0x00, 0x00, 0x00];
    /// let data_ref: Ref<&[u8], Data> = RefMaker::<_, Data>::new(bytes).parse().unwrap();
    /// assert_eq!(data_ref.0, 1);
    ///
    /// // errors if buffer is undersized
    /// let bytes: &[u8] = &[0x01, 0x02, 0x03];
    /// let parse_error = RefMaker::<_, Data>::new(bytes).parse()
    ///     .expect_err("Should error");
    /// assert_eq!(format!("{:?}", parse_error),
    ///     "Buffer is undersized at 3 bytes (need 4 bytes)!");
    ///
    /// // errors if the byte buffer is misaligned
    /// let bytes = [1u8, 2, 3, 4, 5, 6, 7, 8];
    /// let parse_error = RefMaker::<_, Data>::new(&bytes[1..5]).parse()
    ///     .expect_err("Should error");
    /// assert_eq!(format!("{:?}", parse_error),
    ///    "Parser error!");
    /// ```
    pub fn parse(self) -> anyhow::Result<Ref<B, T>> {
        self.ensure_fit()?;
        Ref::<B, T>::new(self.buf).context("Parser error!")
    }

    /// Splits the internal buffer into a `RefMaker` containing a buffer with
    /// exactly `size_of::<T>()` bytes and the remaining tail of the previous
    /// internal buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    ///
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8];
    /// let (prefix_rm, tail) = RefMaker::<_, u32>::new(bytes).from_prefix_with_tail().unwrap();
    /// assert_eq!(prefix_rm.bytes(), &[1,2,3,4]);
    /// assert_eq!(tail, &[5,6,7,8]);
    /// ```
    pub fn from_prefix_with_tail(self) -> anyhow::Result<(Self, B)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), tail))
    }

    /// Splits the buffer into two `RefMaker`s, with the first containing the
    /// first `size_of::<T>()` bytes and the second containing the remaining
    /// tail buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    ///
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8,9,10];
    /// let (prefix_rm, tail) = RefMaker::<_, u32>::new(bytes).split_prefix().unwrap();
    /// assert_eq!(prefix_rm.bytes(), &[1,2,3,4]);
    /// assert_eq!(tail.bytes(), &[5,6,7,8,9,10]);
    /// ```
    pub fn split_prefix(self) -> anyhow::Result<(Self, Self)> {
        self.ensure_fit()?;
        let (head, tail) = self.buf.split_at(Self::target_size());
        Ok((Self::new(head), Self::new(tail)))
    }

    /// Returns a `RefMaker` containing only the first `size_of::<T>()` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8,9,10];
    /// let prefix_rm = RefMaker::<_, u32>::new(bytes).from_prefix().unwrap();
    /// assert_eq!(prefix_rm.bytes(), &[1,2,3,4]);
    /// ```
    pub fn from_prefix(self) -> anyhow::Result<Self> {
        Ok(Self::from_prefix_with_tail(self)?.0)
    }

    /// Splits the buffer into a `RefMaker` containing the last `size_of::<T>()`
    /// bytes as [RefMaker] and the preceding bytes as a buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8,9,10];
    /// let (suffix_rm, head) = RefMaker::<_, u32>::new(bytes).from_suffix_with_head().unwrap();
    /// assert_eq!(suffix_rm.bytes(), &[7,8,9,10]);
    /// assert_eq!(head, &[1,2,3,4,5,6]);
    /// ```
    pub fn from_suffix_with_head(self) -> anyhow::Result<(Self, B)> {
        self.ensure_fit()?;
        let point = self.bytes().len() - Self::target_size();
        let (head, tail) = self.buf.split_at(point);
        Ok((Self::new(tail), head))
    }

    /// Splits the buffer into two `RefMaker`s, with the second containing the
    /// last `size_of::<T>()` bytes, and the first containing the remaining
    /// preceding bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8,9,10];
    /// let (head, tail) = RefMaker::<_, u32>::new(bytes).split_suffix().unwrap();
    /// assert_eq!(head.bytes(), &[1,2,3,4,5,6]);
    /// assert_eq!(tail.bytes(), &[7,8,9,10]);
    /// ```
    pub fn split_suffix(self) -> anyhow::Result<(Self, Self)> {
        self.ensure_fit()?;
        let point = self.bytes().len() - Self::target_size();
        let (head, tail) = self.buf.split_at(point);
        Ok((Self::new(head), Self::new(tail)))
    }

    /// Returns a `RefMaker` containing only the last `target_size()` bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8,9,10];
    /// let suffix_rm = RefMaker::<_, u32>::new(bytes).from_suffix().unwrap();
    /// assert_eq!(suffix_rm.bytes(), &[7,8,9,10]);
    /// ```
    pub fn from_suffix(self) -> anyhow::Result<Self> {
        Ok(Self::from_suffix_with_head(self)?.0)
    }

    /// Returns a reference to the underlying bytes.
    pub fn bytes(&self) -> &[u8] {
        self.buf().deref()
    }

    /// Ensures that the buffer is large enough to hold a `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    ///
    /// ```
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// let bytes: &[u8] = &[1,2,3,4,5,6,7,8,9,10];
    /// let rm = RefMaker::<_, u32>::new(bytes);
    /// rm.ensure_fit().unwrap();
    ///
    /// let bytes: &[u8] = &[1,2,3];
    /// let rm = RefMaker::<_, u32>::new(bytes);
    /// assert!(rm.ensure_fit().is_err());
    /// ```
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
    /// Creates a zeroized reference of type `T` from the buffer.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is undersized.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};    ///
    /// # use rosenpass_util::zerocopy::RefMaker;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data([u8; 4]);
    ///
    /// let mut bytes = [0xFF; 4];
    /// let data_ref: Ref<&mut [u8], Data> = RefMaker::<_, Data>::new(&mut bytes[..]).make_zeroized().unwrap();
    /// assert_eq!(data_ref.0, [0,0,0,0]);
    /// ```
    pub fn make_zeroized(self) -> anyhow::Result<Ref<B, T>> {
        self.zeroized().parse()
    }

    /// Returns a mutable reference to the underlying bytes.
    pub fn bytes_mut(&mut self) -> &mut [u8] {
        self.buf_mut().deref_mut()
    }
}

impl<B: ByteSliceMut, T> Zeroize for RefMaker<B, T> {
    fn zeroize(&mut self) {
        self.bytes_mut().zeroize()
    }
}
