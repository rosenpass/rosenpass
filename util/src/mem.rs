//!
//! This module provides functions for copying data, concatenating byte arrays,
//! and various traits and types that help manage values, including preventing
//! drops, discarding results, and swapping values.

use std::borrow::{Borrow, BorrowMut};
use std::mem::{forget, swap};
use std::ops::{Deref, DerefMut};
use rosenpass_to::{with_destination, To};

// TODO: Zeroize result?
/// Concatenate multiple byte slices into a fixed-size byte array.
///
/// # Panics
///
/// Panics if the concatenated length does not match the declared length.
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::cat;
/// let arr = cat!(6; b"abc", b"def");
/// assert_eq!(&arr, b"abcdef");
///
/// let err = std::panic::catch_unwind(|| cat!(5; b"abc", b"def"));
/// assert!(matches!(err, Err(_)));
///
/// let err = std::panic::catch_unwind(|| cat!(7; b"abc", b"def"));
/// assert!(matches!(err, Err(_)));
/// ```
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
/// Copy all bytes from `src` to `dst`
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::mem::cpy;
/// use rosenpass_to::To;
///
/// let src = [1, 2, 3, 4];
/// let mut dst = [0; 4];
/// cpy(&src).to(&mut dst);
/// assert_eq!(dst, [1, 2, 3, 4]);
/// ```
pub fn cpy<'a, F: Borrow<[u8]> + ?Sized>(src: &'a F) -> impl To<[u8], ()> + 'a {
    with_destination(move |dst: &mut [u8]| {
        let src_slice = src.borrow();
        assert_eq!(src_slice.len(), dst.len());
        dst.copy_from_slice(src_slice);
    })
}

/// Copy as many bytes as possible from `src` to `dst`
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::mem::cpy_min;
/// use rosenpass_to::To;
///
/// let src = [1, 2, 3, 4];
/// let mut dst = [0; 3];
/// cpy_min(&src).to(&mut dst);
/// assert_eq!(dst, [1, 2, 3]);
/// ```
pub fn cpy_min<'a, F: Borrow<[u8]> + ?Sized>(src: &'a F) -> impl To<[u8], ()> + 'a {
    with_destination(move |dst: &mut [u8]| {
        let src_slice = src.borrow();
        let count = std::cmp::min(src_slice.len(), dst.len());
        dst[..count].copy_from_slice(&src_slice[..count]);
    })
}

/// Wrapper type to inhibit calling [std::mem::Drop] when the underlying
/// variable is freed
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::mem::Forgetting;
/// let f = Forgetting::new(String::from("hello"));
/// assert_eq!(&*f, "hello");
/// let val = f.extract();
/// assert_eq!(val, "hello");
/// ```
#[derive(PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Default)]
pub struct Forgetting<T> {
    value: Option<T>,
}

impl<T> Forgetting<T> {
    /// Create a new `Forgetting` wrapping `value`.
    pub fn new(value: T) -> Self {
        Self { value: Some(value) }
    }

    /// Consume and return the inner value.
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
///
/// # Examples
///
/// ```rust
/// # use rosenpass_util::mem::DiscardResultExt;
/// let result: () = (|| { return 42 })().discard_result(); // Just discard
/// ```
pub trait DiscardResultExt {
    /// Consumes and discards a value without doing anything with it.
    fn discard_result(self);
}

impl<T> DiscardResultExt for T {
    fn discard_result(self) {}
}

/// Trait that provides a method to explicitly forget values.
///
/// # Examples
///
/// ```rust
/// # use rosenpass_util::mem::ForgetExt;
/// let s = String::from("no drop");
/// s.forget(); // destructor not run
/// ```
pub trait ForgetExt {
    /// Forget the value.
    fn forget(self);
}

impl<T> ForgetExt for T {
    fn forget(self) {
        std::mem::forget(self)
    }
}

/// Extension trait that provides methods for swapping values.
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::mem::SwapWithExt;
/// let mut x = 10;
/// let mut y = x.swap_with(20);
/// assert_eq!(x, 20);
/// assert_eq!(y, 10);
/// y.swap_with_mut(&mut x);
/// assert_eq!(x, 10);
/// assert_eq!(y, 20);
/// ```
pub trait SwapWithExt {
    /// Swap values and return the old value of `self`.
    fn swap_with(&mut self, other: Self) -> Self;
    /// Swap values in place with another mutable reference.
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
///
/// # Examples
///
/// ```rust
/// # use rosenpass_util::mem::SwapWithDefaultExt;
/// let mut s = String::from("abc");
/// let old = s.swap_with_default();
/// assert_eq!(old, "abc");
/// assert_eq!(s, "");
/// ```
pub trait SwapWithDefaultExt {
    /// Swap with `Self::default()`.
    fn swap_with_default(&mut self) -> Self;
}

impl<T: Default> SwapWithDefaultExt for T {
    fn swap_with_default(&mut self) -> Self {
        self.swap_with(Self::default())
    }
}

/// Extension trait that provides a method to explicitly move values.
///
/// # Examples
///
/// ```rust
/// # use std::rc::Rc;
/// use rosenpass_util::mem::MoveExt;
/// let val = 42;
/// let another_val = val.move_here();
/// assert_eq!(another_val, 42);
/// // val is now inaccessible
///
/// let value = Rc::new(42);
/// let clone = Rc::clone(&value);
///
/// assert_eq!(Rc::strong_count(&value), 2);
///
/// clone.move_here(); // this will drop the second reference
///
/// assert_eq!(Rc::strong_count(&value), 1);
/// ```
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

#[cfg(test)]
mod test_forgetting {
    use crate::mem::Forgetting;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering::SeqCst;
    use std::sync::Arc;

    #[test]
    fn test_forgetting() {
        let drop_was_called = Arc::new(AtomicBool::new(false));
        struct SetFlagOnDrop(Arc<AtomicBool>);
        impl Drop for SetFlagOnDrop {
            fn drop(&mut self) {
                self.0.store(true, SeqCst);
            }
        }
        drop(SetFlagOnDrop(drop_was_called.clone()));
        assert!(drop_was_called.load(SeqCst));
        // reset flag and use Forgetting
        drop_was_called.store(false, SeqCst);
        let forgetting = Forgetting::new(SetFlagOnDrop(drop_was_called.clone()));
        drop(forgetting);
        assert_eq!(drop_was_called.load(SeqCst), false);
    }
}
