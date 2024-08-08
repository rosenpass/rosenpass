use zerocopy::{ByteSlice, ByteSliceMut, Ref};

use super::RefMaker;

pub trait ZerocopySliceExt: Sized + ByteSlice {
    fn zk_ref_maker<T>(self) -> RefMaker<Self, T> {
        RefMaker::<Self, T>::new(self)
    }

    fn zk_parse<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().parse()
    }

    fn zk_parse_prefix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_prefix()?.parse()
    }

    fn zk_parse_suffix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_suffix()?.parse()
    }
}

impl<B: ByteSlice> ZerocopySliceExt for B {}

pub trait ZerocopyMutSliceExt: ZerocopySliceExt + Sized + ByteSliceMut {
    fn zk_zeroized<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().make_zeroized()
    }

    fn zk_zeroized_from_prefix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_prefix()?.make_zeroized()
    }

    fn zk_zeroized_from_suffix<T>(self) -> anyhow::Result<Ref<Self, T>> {
        self.zk_ref_maker().from_suffix()?.make_zeroized()
    }
}

impl<B: ByteSliceMut> ZerocopyMutSliceExt for B {}
