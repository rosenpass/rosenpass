use zerocopy::{ByteSlice, ByteSliceMut, Ref};

pub trait ZerocopyEmancipateExt<B, T> {
    fn emancipate(&self) -> Ref<&[u8], T>;
}

pub trait ZerocopyEmancipateMutExt<B, T> {
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
