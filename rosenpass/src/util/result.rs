use std::result::Result;

/// Trait for container types that guarantee successful unwrapping.
///
/// The `.guaranteed()` function can be used over unwrap to show that
/// the function will not panic.
///
/// Implementations must not panic.
trait GuaranteedValue {
    type Value;

    /// Extract the contained value while being panic-safe, like .unwrap()
    ///
    /// # Panic Safety
    ///
    /// Implementations of guaranteed() must not panic.
    fn guaranteed(self) -> Self::Value;
}

/// An error type to indicate that an error will not occur.
///
/// This is a nullary enum; i.e. an instance of this enum can not be created.
pub(crate) enum NeverFails {}

/// A result type that never contains an error.
///
/// This is mostly useful in generic contexts.
///
/// # Examples
///
/// ```
/// use std::num::Wrapping;
/// use std::result::Result;
///
/// trait FailableAddition {
///   type Error;
///   fn failable_addition(&self, other: &Self) -> Result<Self, Self::Error>;
/// }
///
/// struct OverflowError;
///
/// impl<T> FailableAddition for Wrapping<T> {
///   type Error = NeverFails;
///   fn failable_addition(&self, other: &Self) -> Guaranteed<Self> {
///     self + other
///   }
/// }
///
/// impl<T> FailableAddition for u32 {
///   type Error = NeverFails;
///   fn failable_addition(&self, other: &Self) -> Guaranteed<Self> {
///     match self.checked_add(*other) {
///         Some(v) => Ok(v),
///         None => Err(OverflowError),
///     }
///   }
/// }
///
/// fn failable_multiply<T>(a: &T, b: u32)
///         -> Result<T, T::Error> {
///     where
///         T: FailableAddition<Error> {
///     let mut accu = a.failable_addition(a)?;
///     for _ in ..(b-1) {
///         accu.failable_addition(a)?;
///     }
///     Ok(accu)
/// }
///
/// // We can use .guaranteed() with Wrapping<u32>, since the operation uses
/// // the NeverFails error type.
/// // We can also use unwrap which just happens to not raise an error.
/// assert_eq!(failable_multiply(&Wrapping::new(42u32), 3).guaranteed(), 126);
/// assert_eq!(failable_multiply(&Wrapping::new(42u32), 3).unwrap(), 126);
///
/// // We can not use .guaranteed() with u32, since there can be an error.
/// // We can however use unwrap(), which may panic
/// assert_eq!(failable_multiply(&42u32, 3).guaranteed(), 126); // COMPILER ERROR
/// assert_eq!(failable_multiply(&42u32, 3).unwrap(), 126);
/// ```
pub(crate) type Guaranteed<T> = Result<T, NeverFails>;

impl<T> GuaranteedValue for Guaranteed<T> {
    type Value = T;
    fn guaranteed(self) -> Self::Value {
        self.unwrap();
    }
}
