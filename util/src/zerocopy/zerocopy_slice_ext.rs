//! Extension traits for parsing slices into [`zerocopy::Ref`] values using the
//! [`RefMaker`] abstraction.

use zerocopy::{ByteSlice, ByteSliceMut, Ref};

use super::RefMaker;

/// Extension trait for performing zero-copy parsing operations on byte slices.
///
/// This trait adds methods for creating [`Ref`](zerocopy::Ref) references from
/// slices by using the [`RefMaker`] type internally.
pub trait ZerocopySliceExt: Sized + ByteSlice {
    /// Creates a new `RefMaker` for the given slice.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::{RefMaker, ZerocopySliceExt};
    ///
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data(u32);
    ///
    /// let rm: RefMaker<&[u8], Data> = [3,0,0,0].zk_ref_maker();
    /// assert_eq!(rm.bytes(), &[3,0,0,0]);
    /// assert_eq!(rm.parse().unwrap().0, 3);
    /// ```
    fn zk_ref_maker<T>(self) -> RefMaker<Self, T> {
        RefMaker::<Self, T>::new(self)
    }

    /// Parses the given slice into a zero-copy reference of the given type `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too small.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::ZerocopySliceExt;
    ///
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data(u16, u16);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 4]);
    /// let bytes = AlignedBuf([0x01,0x02,0x03,0x04]);
    /// let data_ref = bytes.0.zk_parse::<Data>().unwrap();
    /// assert_eq!(data_ref.0, 0x0201);
    /// assert_eq!(data_ref.1, 0x0403);
    /// ```
    fn zk_parse<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().parse()
    }

    /// Parses a prefix of the slice into a zero-copy reference.
    ///
    /// Uses only the first [std::mem::size_of::<T>()] bytes of `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too small.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::ZerocopySliceExt;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Header(u32);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 8]);
    /// let bytes = AlignedBuf([0xAA, 0xBB, 0xCC, 0xDD,
    /// 0x00, 0x10, 0x20, 0x30]);
    ///
    /// let header_ref = bytes.0.zk_parse_prefix::<Header>().unwrap();
    /// assert_eq!(header_ref.0, 0xDDCCBBAA);
    /// ```
    fn zk_parse_prefix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_prefix()?.parse()
    }

    /// Parses a suffix of the slice into a zero-copy reference.
    ///
    /// Uses only the last [std::mem::size_of::<T>()] bytes of `T`.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too small.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::ZerocopySliceExt;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Header(u32);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 8]);
    /// let bytes = AlignedBuf([0xAA, 0xBB, 0xCC, 0xDD,
    /// 0x00, 0x10, 0x20, 0x30]);
    ///
    /// let header_ref = bytes.0.zk_parse_suffix::<Header>().unwrap();
    /// assert_eq!(header_ref.0, 0x30201000);
    /// ```
    fn zk_parse_suffix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_suffix()?.parse()
    }
}

impl<B: ByteSlice> ZerocopySliceExt for B {}

/// Extension trait for zero-copy parsing of mutable slices with zeroization
/// capabilities.
///
/// Provides convenience methods to create zero-initialized references.
pub trait ZerocopyMutSliceExt: ZerocopySliceExt + Sized + ByteSliceMut {
    /// Creates a new zeroized reference from the entire slice.
    ///
    /// This zeroizes the slice first, then provides a `Ref`.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too small.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::ZerocopyMutSliceExt;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data([u8; 4]);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 4]);
    /// let mut bytes = AlignedBuf([0xFF; 4]);
    /// let data_ref = bytes.0.zk_zeroized::<Data>().unwrap();
    /// assert_eq!(data_ref.0, [0,0,0,0]);
    /// assert_eq!(bytes.0, [0, 0, 0, 0]);
    /// ```
    fn zk_zeroized<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().make_zeroized()
    }

    /// Creates a new zeroized reference from the prefix of the slice.
    ///
    /// Zeroizes the first `target_size()` bytes of the slice, then returns a
    /// `Ref`.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too small.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::ZerocopyMutSliceExt;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data([u8; 4]);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 6]);
    /// let mut bytes = AlignedBuf([0xFF; 6]);
    /// let data_ref = bytes.0.zk_zeroized_from_prefix::<Data>().unwrap();
    /// assert_eq!(data_ref.0, [0,0,0,0]);
    /// assert_eq!(bytes.0, [0, 0, 0, 0, 0xFF, 0xFF]);
    /// ```
    fn zk_zeroized_from_prefix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_prefix()?.make_zeroized()
    }

    /// Creates a new zeroized reference from the suffix of the slice.
    ///
    /// Zeroizes the last `target_size()` bytes of the slice, then returns a
    /// `Ref`.
    ///
    /// # Errors
    ///
    /// Returns an error if the slice is too small.
    ///
    /// # Example
    ///
    /// ```
    /// # use zerocopy::{AsBytes, FromBytes, FromZeroes};
    /// # use rosenpass_util::zerocopy::ZerocopyMutSliceExt;
    /// #[derive(FromBytes, FromZeroes, AsBytes)]
    /// #[repr(C)]
    /// struct Data([u8; 4]);
    /// #[repr(align(4))]
    /// struct AlignedBuf([u8; 6]);
    /// let mut bytes = AlignedBuf([0xFF; 6]);
    /// let data_ref = bytes.0.zk_zeroized_from_suffix::<Data>().unwrap();
    /// assert_eq!(data_ref.0, [0,0,0,0]);
    /// assert_eq!(bytes.0, [0xFF, 0xFF, 0, 0, 0, 0]);
    /// ```
    fn zk_zeroized_from_suffix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_suffix()?.make_zeroized()
    }
}

impl<B: ByteSliceMut> ZerocopyMutSliceExt for B {}
