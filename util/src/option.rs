/// A helper trait for turning any type value into `Some(value)`.
///
/// # Examples
///
/// ```
/// use rosenpass_util::option::SomeExt;
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
