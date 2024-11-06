use std::convert::Infallible;

/// Try block basically…returns a result and allows the use of the question mark operator inside
#[macro_export]
macro_rules! attempt {
    ($block:expr) => {
        (|| -> ::anyhow::Result<_> { $block })()
    };
}

/// Trait for the ok operation, which provides a way to convert a value into a Result
pub trait OkExt<E>: Sized {
    /// Wraps a value in a Result::Ok variant
    fn ok(self) -> Result<Self, E>;
}

impl<T, E> OkExt<E> for T {
    fn ok(self) -> Result<Self, E> {
        Ok(self)
    }
}

/// Trait for container types that guarantee successful unwrapping.
///
/// The `.guaranteed()` function can be used over unwrap to show that
/// the function will not panic.
///
/// Implementations must not panic.
pub trait GuaranteedValue {
    /// The value type that will be returned by guaranteed()
    type Value;

    /// Extract the contained value while being panic-safe, like .unwrap()
    ///
    /// # Panic Safety
    ///
    /// Implementations of guaranteed() must not panic.
    fn guaranteed(self) -> Self::Value;
}

/// Extension trait for adding finally operation to types
pub trait FinallyExt {
    /// Executes a closure with mutable access to self and returns self
    ///
    /// The closure is guaranteed to be executed before returning.
    fn finally<F: FnOnce(&mut Self)>(self, f: F) -> Self;
}

impl<T, E> FinallyExt for Result<T, E> {
    fn finally<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self);
        self
    }
}

impl<T> FinallyExt for Option<T> {
    fn finally<F: FnOnce(&mut Self)>(mut self, f: F) -> Self {
        f(&mut self);
        self
    }
}

/// A result type that never contains an error.
///
/// This is mostly useful in generic contexts.
///
/// # Examples
///
/// ```
/// use std::num::Wrapping;
/// use std::result::Result;
/// use std::convert::Infallible;
/// use std::ops::Add;
///
/// use rosenpass_util::result::{Guaranteed, GuaranteedValue};
///
/// trait FailableAddition: Sized {
///   type Error;
///   fn failable_addition(&self, other: &Self) -> Result<Self, Self::Error>;
/// }
///
/// #[derive(Copy, Clone, Debug, Eq, PartialEq)]
/// struct OverflowError;
///
/// impl<T> FailableAddition for Wrapping<T>
///   where for <'a> &'a Wrapping<T>: Add<Output = Wrapping<T>> {
///   type Error = Infallible;
///   fn failable_addition(&self, other: &Self) -> Guaranteed<Self> {
///     Ok(self + other)
///   }
/// }
///
/// impl FailableAddition for u32 {
///   type Error = OverflowError;
///   fn failable_addition(&self, other: &Self) -> Result<Self, Self::Error> {
///     match self.checked_add(*other) {
///         Some(v) => Ok(v),
///         None => Err(OverflowError),
///     }
///   }
/// }
///
/// fn failable_multiply<T>(a: &T, b: u32)
///         -> Result<T, T::Error>
///     where
///         T: FailableAddition {
///     assert!(b >= 2); // Acceptable only because this is for demonstration purposes
///     let mut accu = a.failable_addition(a)?;
///     for _ in 2..b {
///         accu = accu.failable_addition(a)?;
///     }
///     Ok(accu)
/// }
///
/// // We can use .guaranteed() with Wrapping<u32>, since the operation uses
/// // the Infallible error type.
/// // We can also use unwrap which just happens to not raise an error.
/// assert_eq!(failable_multiply(&Wrapping(42u32), 3).guaranteed(), Wrapping(126));
/// assert_eq!(failable_multiply(&Wrapping(42u32), 3).unwrap(), Wrapping(126));
///
/// // We can not use .guaranteed() with u32, since there can be an error.
/// // We can however use unwrap(), which may panic
/// //assert_eq!(failable_multiply(&42u32, 3).guaranteed(), 126); // COMPILER ERROR
/// assert_eq!(failable_multiply(&42u32, 3).unwrap(), 126);
/// ```
pub type Guaranteed<T> = Result<T, Infallible>;

impl<T> GuaranteedValue for Guaranteed<T> {
    type Value = T;
    fn guaranteed(self) -> Self::Value {
        self.unwrap()
    }
}

/// Checks a condition is true and returns an error if not.
///
/// # Examples
///
/// ```rust
/// # use rosenpass_util::result::ensure_or;
/// let result = ensure_or(5 > 3, "not greater");
/// assert!(result.is_ok());
///
/// let result = ensure_or(5 < 3, "not less");
/// assert!(result.is_err());
/// ```
pub fn ensure_or<E>(b: bool, err: E) -> Result<(), E> {
    match b {
        true => Ok(()),
        false => Err(err),
    }
}

/// Evaluates to an error if the condition is true.
///
/// # Examples
///
/// ```rust
/// # use rosenpass_util::result::bail_if;
/// let result = bail_if(false, "not bailed");
/// assert!(result.is_ok());
///
/// let result = bail_if(true, "bailed");
/// assert!(result.is_err());
/// ```
pub fn bail_if<E>(b: bool, err: E) -> Result<(), E> {
    ensure_or(!b, err)
}
