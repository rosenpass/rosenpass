use crate::{DstCoercion, To};

/// Alias for [To::to] moving the destination to the left.
///
/// This provides similar haptics to the let assignment syntax is rust, which also keeps
/// the variable to assign to on the left and the generating function on the right.
pub fn to<Coercable, Src, Dst, Ret>(dst: &mut Coercable, src: Src) -> Ret
where
    Coercable: ?Sized + DstCoercion<Dst>,
    Src: To<Dst, Ret>,
    Dst: ?Sized,
{
    src.to(dst.coerce_dest())
}
