use zerocopy::{ByteSlice, ByteSliceMut, Ref};

/// A trait for converting a `Ref<B, T>` into a `Ref<&[u8], T>`.
pub trait ZerocopyEmancipateExt<B, T> {
    /// Converts this reference into a reference backed by a byte slice.
    fn emancipate(&self) -> Ref<&[u8], T>;
}

/// A trait for converting a `Ref<B, T>` into a mutable `Ref<&mut [u8], T>`.
pub trait ZerocopyEmancipateMutExt<B, T> {
    /// Converts this reference into a mutable reference backed by a byte slice.
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
