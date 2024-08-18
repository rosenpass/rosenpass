pub trait SomeExt: Sized {
    fn some(self) -> Option<Self> {
        Some(self)
    }
}

impl<T> SomeExt for T {}
