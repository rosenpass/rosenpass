use zerocopy::{ByteSlice, ByteSliceMut, Ref};

use super::RefMaker;

/// Extension trait for zero-copy slice operations.
pub trait ZerocopySliceExt: Sized + ByteSlice {
    /// Creates a new `RefMaker` for the given slice.
    fn zk_ref_maker<T>(self) -> RefMaker<Self, T> {
        RefMaker::<Self, T>::new(self)
    }

    /// Parses the slice into a zero-copy reference.
    fn zk_parse<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().parse()
    }

    /// Parses a prefix of the slice into a zero-copy reference.
    fn zk_parse_prefix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_prefix()?.parse()
    }

    /// Parses a suffix of the slice into a zero-copy reference.
    fn zk_parse_suffix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_suffix()?.parse()
    }
}

impl<B: ByteSlice> ZerocopySliceExt for B {}

/// Extension trait for zero-copy slice operations with mutable slices.
pub trait ZerocopyMutSliceExt: ZerocopySliceExt + Sized + ByteSliceMut {
    /// Creates a new zeroed reference from the entire slice.
    fn zk_zeroized<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().make_zeroized()
    }

    /// Creates a new zeroed reference from a prefix of the slice.
    fn zk_zeroized_from_prefix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_prefix()?.make_zeroized()
    }

    /// Creates a new zeroed reference from a suffix of the slice.
    fn zk_zeroized_from_suffix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_suffix()?.make_zeroized()
    }
}

impl<B: ByteSliceMut> ZerocopyMutSliceExt for B {}
