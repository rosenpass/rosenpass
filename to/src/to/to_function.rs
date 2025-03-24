//! This module provides the [To::to] function which allows to use functions with destination in
//! a manner akin to that of a variable assignment. See [To::to] for more details.

use crate::{DstCoercion, To};

/// Alias for [To::to] moving the destination to the left.
///
/// This provides similar haptics to the let assignment syntax in rust, which also keeps
/// the variable to assign to on the left and the generating function on the right.
///
/// # Example
/// ```rust
/// // Using the to function to have data flowing from the right to the left,
/// // performing something akin to a variable assignment.
/// use rosenpass_to::ops::copy_slice_least;
/// use rosenpass_to::to;
/// 
/// let mut dst = b"           ".to_vec();
/// to(&mut dst[..], copy_slice_least(b"Hello World"));
/// assert_eq!(&dst[..], b"Hello World");
/// 
/// // Compared to using the method syntax:
/// let mut dst2 = b"           ".to_vec();
/// copy_slice_least(b"Hello World").to(&mut dst2[..]);
/// assert_eq!(&dst2[..], b"Hello World");
/// ```
pub fn to<Coercable, Src, Dst, Ret>(dst: &mut Coercable, src: Src) -> Ret
where
    Coercable: ?Sized + DstCoercion<Dst>,
    Src: To<Dst, Ret>,
    Dst: ?Sized,
{
    src.to(dst.coerce_dest())
}
