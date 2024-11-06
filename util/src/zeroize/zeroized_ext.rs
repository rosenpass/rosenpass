use zeroize::Zeroize;

/// Extension trait providing a method for zeroizing a value and returning it
pub trait ZeroizedExt: Zeroize + Sized {
    /// Zeroizes the value in place and returns self
    fn zeroized(mut self) -> Self {
        self.zeroize();
        self
    }
}

impl<T: Zeroize + Sized> ZeroizedExt for T {}
