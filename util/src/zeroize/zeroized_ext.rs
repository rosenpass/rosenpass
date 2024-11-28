use zeroize::Zeroize;

/// Extension trait providing a method for zeroizing a value and returning it
///
/// # Examples
///
/// ```rust
/// use zeroize::Zeroize;
/// use rosenpass_util::zeroize::ZeroizedExt;
///
/// let mut value = String::from("hello");
/// value.zeroize();
/// assert_eq!(value, "");
///
/// let value = String::from("hello").zeroized();
/// assert_eq!(value, "");
/// ```
pub trait ZeroizedExt: Zeroize + Sized {
    /// Zeroizes the value in place and returns self
    fn zeroized(mut self) -> Self {
        self.zeroize();
        self
    }
}

impl<T: Zeroize + Sized> ZeroizedExt for T {}
