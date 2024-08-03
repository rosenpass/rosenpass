use zeroize::Zeroize;

pub trait ZeroizedExt: Zeroize + Sized {
    fn zeroized(mut self) -> Self {
        self.zeroize();
        self
    }
}

impl<T: Zeroize + Sized> ZeroizedExt for T {}
