//! Extension traits for converting `Ref<B, T>` into references backed by
//! standard slices.

use zerocopy::{ByteSlice, ByteSliceMut, Ref};

/// A trait for converting a `Ref<B, T>` into a `Ref<&[u8], T>`.
///
/// This can be useful when you need a reference that is tied to a slice rather
/// than the original buffer type `B`.
///
/// Note: This trait is implemented to [Ref](zerocopy::Ref) of byte slices
/// (`&[u8]`).
pub trait ZerocopyEmancipateExt<B, T> {
    /// Converts this reference into a reference backed by a plain byte slice.
    ///
    /// # Example
    ///
    /// ```
    /// # use std::ops::Deref;
    /// # use zerocopy::{AsBytes, ByteSlice, FromBytes, FromZeroes, Ref};
    /// # use rosenpass_util::zerocopy::ZerocopyEmancipateExt;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data(u32);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 4]);
    /// let bytes = AlignedBuf([0xAA, 0xBB, 0xCC, 0xDD]);
    /// let r = Ref::<&[u8], Data>::new(&bytes.0).unwrap();
    /// let emancipated: Ref<&[u8], Data> = r.emancipate(); // same data, but guaranteed &[u8] backing
    /// assert_eq!(emancipated.0, 0xDDCCBBAA);
    /// ```
    fn emancipate(&self) -> Ref<&[u8], T>;
}

/// A trait for converting a `Ref<B, T>` into a mutable `Ref<&mut [u8], T>`.
///
/// Similar to [`ZerocopyEmancipateExt`], but for mutable references.
///
/// Note: this trait is implemented to [Ref](zerocopy::Ref) of mutable byte
/// slices (`&mut [u8]`).
pub trait ZerocopyEmancipateMutExt<B, T> {
    /// Converts this reference into a mutable reference backed by a plain
    /// mutable byte slice.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};
    /// # use rosenpass_util::zerocopy::{ZerocopyEmancipateMutExt};
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data(u32);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 4]);
    /// let mut bytes = AlignedBuf([0xAA, 0xBB, 0xCC, 0xDD]);
    /// let mut r = Ref::<&mut [u8], Data>::new(&mut bytes.0).unwrap();
    /// let mut emancipated: Ref<&mut [u8], Data> = r.emancipate_mut(); // same data, but guaranteed &[u8] backing
    /// assert_eq!(emancipated.0, 0xDDCCBBAA);
    /// emancipated.0 = 0x33221100;
    /// drop(emancipated);
    /// assert_eq!(bytes.0, [0x00, 0x11, 0x22, 0x33]);
    /// ```
    fn emancipate_mut(&mut self) -> Ref<&mut [u8], T>;
}

impl<B, T> ZerocopyEmancipateExt<B, T> for Ref<B, T>
where
    B: ByteSlice,
{
    fn emancipate(&self) -> Ref<&[u8], T> {
        Ref::new(self.bytes()).unwrap()
    }
}

impl<B, T> ZerocopyEmancipateMutExt<B, T> for Ref<B, T>
where
    B: ByteSliceMut,
{
    fn emancipate_mut(&mut self) -> Ref<&mut [u8], T> {
        Ref::new(self.bytes_mut()).unwrap()
    }
}
