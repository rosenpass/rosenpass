//! Helpers for string formatting with the debug formatter; extensions for [std::fmt::Debug]

use std::any::type_name;
use std::borrow::{Borrow, BorrowMut};
use std::ops::{Deref, DerefMut};

/// Debug formatter which just prints the type name;
/// used to wrap values which do not support the Debug
/// trait themselves
///
/// # Examples
///
/// ```rust
/// use rosenpass_util::fmt::debug::NullDebug;
///
/// // Does not implement debug
/// struct NoDebug;
///
/// #[derive(Debug)]
/// struct ShouldSupportDebug {
///     #[allow(dead_code)]
///     no_debug: NullDebug<NoDebug>,
/// }
///
/// let val = ShouldSupportDebug {
///     no_debug: NullDebug(NoDebug),
/// };
/// ```
pub struct NullDebug<T>(pub T);

impl<T> std::fmt::Debug for NullDebug<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("NullDebug<")?;
        f.write_str(type_name::<T>())?;
        f.write_str(">")?;
        Ok(())
    }
}

impl<T> From<T> for NullDebug<T> {
    fn from(value: T) -> Self {
        NullDebug(value)
    }
}

impl<T> Deref for NullDebug<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.borrow()
    }
}

impl<T> DerefMut for NullDebug<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.borrow_mut()
    }
}

impl<T> Borrow<T> for NullDebug<T> {
    fn borrow(&self) -> &T {
        self.deref()
    }
}

impl<T> BorrowMut<T> for NullDebug<T> {
    fn borrow_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}

impl<T> AsRef<T> for NullDebug<T> {
    fn as_ref(&self) -> &T {
        self.deref()
    }
}

impl<T> AsMut<T> for NullDebug<T> {
    fn as_mut(&mut self) -> &mut T {
        self.deref_mut()
    }
}
