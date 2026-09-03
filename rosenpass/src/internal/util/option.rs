/// A helper trait for turning any type value into `Some(value)`.
///
/// # Examples
///
#[cfg_attr(feature = "expose_internal_modules", doc = "```")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
/// use rosenpass::internal::util::option::SomeExt;
///
/// let x = 42;
/// let y = x.some();
///
/// assert_eq!(y, Some(42));
/// ```
pub trait SomeExt: Sized {
    /// Wraps the calling value in `Some()`.
    fn some(self) -> Option<Self> {
        Some(self)
    }
}

impl<T> SomeExt for T {}
