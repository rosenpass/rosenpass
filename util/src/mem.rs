use std::borrow::{Borrow, BorrowMut};
use std::cmp::min;
use std::mem::{forget, swap};
use std::ops::{Deref, DerefMut};

/// Concatenate two byte arrays
// TODO: Zeroize result?
#[macro_export]
macro_rules! cat {
    ($len:expr; $($toks:expr),+) => {{
        let mut buf = [0u8; $len];
        let mut off = 0;
        $({
            let tok = $toks;
            let tr = ::std::borrow::Borrow::<[u8]>::borrow(tok);
            (&mut buf[off..(off + tr.len())]).copy_from_slice(tr);
            off += tr.len();
        })+
        assert!(off == buf.len(), "Size mismatch in cat!()");
        buf
    }}
}

// TODO: consistent inout ordering
/// Copy all bytes from `src` to `dst`. The lengths must match.
pub fn cpy<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, dst: &mut T) {
    dst.borrow_mut().copy_from_slice(src.borrow());
}

/// Copy from `src` to `dst`. If `src` and `dst` are not of equal length, copy as many bytes as possible.
pub fn cpy_min<T: BorrowMut<[u8]> + ?Sized, F: Borrow<[u8]> + ?Sized>(src: &F, dst: &mut T) {
    let src = src.borrow();
    let dst = dst.borrow_mut();
    let len = min(src.len(), dst.len());
    dst[..len].copy_from_slice(&src[..len]);
}

/// Wrapper type to inhibit calling [std::mem::Drop] when the underlying variable is freed
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Default)]
pub struct Forgetting<T> {
    value: Option<T>,
}

impl<T> Forgetting<T> {
    /// Creates a new `Forgetting<T>` instance containing the given value.
    pub fn new(value: T) -> Self {
        let value = Some(value);
        Self { value }
    }

    /// Extracts and returns the contained value, consuming self.
    pub fn extract(mut self) -> T {
        let mut value = None;
        swap(&mut value, &mut self.value);
        value.unwrap()
    }
}

impl<T> From<T> for Forgetting<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

impl<T> Deref for Forgetting<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value.as_ref().unwrap()
    }
}

impl<T> DerefMut for Forgetting<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value.as_mut().unwrap()
    }
}

impl<T> Borrow<T> for Forgetting<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T> BorrowMut<T> for Forgetting<T> {
    fn borrow_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T> Drop for Forgetting<T> {
    fn drop(&mut self) {
        let mut value = None;
        swap(&mut self.value, &mut value);
        forget(value)
    }
}

/// A trait that provides a method to discard a value without explicitly handling its results.
pub trait DiscardResultExt {
    /// Consumes and discards a value without doing anything with it.
    fn discard_result(self);
}

impl<T> DiscardResultExt for T {
    fn discard_result(self) {}
}

/// Trait that provides a method to explicitly forget values.
pub trait ForgetExt {
    /// Consumes and forgets a value, preventing its destructor from running.
    fn forget(self);
}

impl<T> ForgetExt for T {
    fn forget(self) {
        std::mem::forget(self)
    }
}

/// Extension trait that provides methods for swapping values.
pub trait SwapWithExt {
    /// Takes ownership of `other` and swaps its value with `self`, returning the original value.
    fn swap_with(&mut self, other: Self) -> Self;
    /// Swaps the values between `self` and `other` in place.
    fn swap_with_mut(&mut self, other: &mut Self);
}

impl<T> SwapWithExt for T {
    fn swap_with(&mut self, mut other: Self) -> Self {
        self.swap_with_mut(&mut other);
        other
    }

    fn swap_with_mut(&mut self, other: &mut Self) {
        std::mem::swap(self, other)
    }
}

/// Extension trait that provides methods for swapping values with default values.
pub trait SwapWithDefaultExt {
    /// Takes the current value and replaces it with the default value, returning the original.
    fn swap_with_default(&mut self) -> Self;
}

impl<T: Default> SwapWithDefaultExt for T {
    fn swap_with_default(&mut self) -> Self {
        self.swap_with(Self::default())
    }
}

/// Extension trait that provides a method to explicitly move values.
pub trait MoveExt {
    /// Deliberately move the value
    ///
    /// Usually employed to enforce an object being
    /// dropped after use.
    fn move_here(self) -> Self;
}

impl<T: Sized> MoveExt for T {
    fn move_here(self) -> Self {
        self
    }
}
