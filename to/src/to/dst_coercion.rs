/// Helper performing explicit unsized coercion.
/// Used by the [to](crate::to()) function.
pub trait DstCoercion<Dst: ?Sized> {
    fn coerce_dest(&mut self) -> &mut Dst;
}

impl<T: ?Sized> DstCoercion<T> for T {
    fn coerce_dest(&mut self) -> &mut T {
        self
    }
}

impl<T, const N: usize> DstCoercion<[T]> for [T; N] {
    fn coerce_dest(&mut self) -> &mut [T] {
        self
    }
}
