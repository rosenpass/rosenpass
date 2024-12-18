//! This module provides explicit type coercion from [Sized] types to [?Sized][core::marker::Sized]
//! types. See [DstCoercion] for more details.

/// Helper Trait for performing explicit coercion from [Sized] types to
/// [?Sized][core::marker::Sized] types. It's used by the [to](crate::to()) function.
///
/// We provide blanket implementations for any [Sized] type and for any array of [Sized] types.
///
/// # Example
/// It can be used as follows:
/// ```
/// # use rosenpass_to::DstCoercion;
/// // Consider a sized type like this example:
/// struct SizedStruct {
///     x: u32
/// }
/// // Then we can coerce it to be unsized:
/// let mut sized = SizedStruct { x: 42 };
/// assert_eq!(42, sized.coerce_dest().x);
///
/// // Analogously, we can coerce arrays to slices:
/// let mut sized_array = [1, 2, 3, 4, 5, 6, 7, 8, 9];
/// let un_sized: &[i32] = sized_array.coerce_dest();
/// assert_eq!(un_sized, un_sized);
/// ```
pub trait DstCoercion<Dst: ?Sized> {
    /// Performs an explicit coercion to the destination type.
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
