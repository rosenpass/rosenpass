/// A helper trait for turning any type value into `Some(value)`.
pub trait SomeExt: Sized {
    /// Wraps the calling value in `Some()`.
    fn some(self) -> Option<Self> {
        Some(self)
    }
}

impl<T> SomeExt for T {}
