use crate::To;
use std::marker::PhantomData;

/// A struct that wraps a closure and implements the `To` trait
///
/// This allows passing closures that operate on a destination type `Dst`
/// and return `Ret`.
///
/// # Type Parameters
/// * `Dst` - The destination type the closure operates on
/// * `Ret` - The return type of the closure
/// * `Fun` - The closure type that implements `FnOnce(&mut Dst) -> Ret`
struct ToClosure<Dst, Ret, Fun>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    /// The function to call.
    fun: Fun,
    /// Phantom data to hold the destination type
    _val: PhantomData<Box<Dst>>,
}

/// Implementation of the `To` trait for ToClosure
///
/// This enables calling the wrapped closure with a destination reference.
impl<Dst, Ret, Fun> To<Dst, Ret> for ToClosure<Dst, Ret, Fun>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    /// Execute the wrapped closure with the given destination
    ///
    /// # Arguments
    /// * `out` - Mutable reference to the destination
    fn to(self, out: &mut Dst) -> Ret {
        (self.fun)(out)
    }
}

/// Used to create a function with destination.
///
/// Creates a wrapper that implements the `To` trait for a closure that
/// operates on a destination type.
///
/// # Type Parameters
/// * `Dst` - The destination type the closure operates on
/// * `Ret` - The return type of the closure
/// * `Fun` - The closure type that implements `FnOnce(&mut Dst) -> Ret`
///
/// See the tutorial in [readme.me]..
pub fn with_destination<Dst, Ret, Fun>(fun: Fun) -> impl To<Dst, Ret>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    ToClosure {
        fun,
        _val: PhantomData,
    }
}
