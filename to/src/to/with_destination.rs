//! The module provides the [with_destination] function, which makes it easy to create
//! a [To] from a lambda function. See [with_destination] and the [crate documentation](crate)
//! for more details and examples.

use crate::To;
use std::marker::PhantomData;

/// A struct that wraps a closure and implements the `To` trait.
///
/// This allows passing closures that operate on a destination type `Dst`
/// and return `Ret`. It is only internally used to implement [with_destination].
///
/// # Type Parameters
/// * `Dst` - The destination type the closure operates on.
/// * `Ret` - The return type of the closure.
/// * `Fun` - The closure type that implements `FnOnce(&mut Dst) -> Ret`.
struct ToClosure<Dst, Ret, Fun>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    /// The function to call.
    fun: Fun,
    /// Phantom data to hold the destination type.
    _val: PhantomData<Box<Dst>>,
}

/// Implementation of the `To` trait for ToClosure.
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
    /// See the tutorial in [readme.md] for examples and more explanations.
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
/// See the tutorial in the [crate documentation](crate) for more examples and more explanations.
/// # Example
/// ```
/// use rosenpass_to::with_destination;
/// use rosenpass_to::To;
/// let my_origin_data: [u8; 16]= [2; 16];
/// let times_two = with_destination( move |dst: &mut [u8; 16]| {
///     for (dst, org) in dst.iter_mut().zip(my_origin_data.iter()) {
///         *dst = org * dst.clone();
///     }
/// });
/// let mut dst: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// times_two.to(&mut dst);
/// for i in 0..16 {
///     assert_eq!(dst[i], (2 * i) as u8);
/// }
///
/// ```
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
