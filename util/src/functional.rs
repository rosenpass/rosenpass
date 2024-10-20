//! Syntax sugar & helpers for a functional programming style and method chains

/// Mutate a value; mostly syntactic sugar
///
/// # Examples
///
/// ```
/// use std::borrow::Borrow;
/// use rosenpass_util::functional::{mutating, MutatingExt, sideeffect, SideffectExt, ApplyExt};
/// use rosenpass_util::mem::DiscardResultExt;
///
/// // Say you have a function that takes a mutable reference
/// fn replace<T: Copy + Eq>(slice: &mut [T], targ: T, by: T) {
///     for val in slice.iter_mut() {
///         if *val == targ {
///             *val = by;
///         }
///     }
/// }
///
/// // Or you have some action that you want to perform as a side effect
/// fn count<T: Copy + Eq>(accumulator: &mut usize, slice: &[T], targ: T) {
///     *accumulator += slice.iter()
///         .filter(|e| *e == &targ)
///         .count();
/// }
///
/// // Lets say, you also have a function that actually modifies the value
/// fn rot2<const N : usize>(slice: [u8; N]) -> [u8; N] {
///    let it = slice.iter()
///        .cycle()
///        .skip(2)
///        .take(N);
///
///    let mut ret = [0u8; N];
///    for (no, elm) in it.enumerate() {
///        ret[no] = *elm;
///    }
///
///    ret
/// }
///
/// // Then these function are kind of clunky to use in an expression;
/// // it can be done, but the resulting code is a bit verbose
/// let mut accu = 0;
/// assert_eq!(b"llo_WorldHe", &{
///     let mut buf = b"Hello World".to_owned();
///     count(&mut accu, &buf, b'l');
///     replace(&mut buf, b' ', b'_');
///     rot2(buf)
/// });
/// assert_eq!(accu, 3);
///
/// // Instead you could use mutating for a slightly prettier syntax,
/// // but this makes only sense if you want to apply a single action
/// assert_eq!(b"Hello_World",
///     &mutating(b"Hello World".to_owned(), |buf|
///         replace(buf, b' ', b'_')));
///
/// // The same is the case for sideeffect()
/// assert_eq!(b"Hello World",
///     &sideeffect(b"Hello World".to_owned(), |buf|
///         count(&mut accu, buf, b'l')));
/// assert_eq!(accu, 6);
///
/// // Calling rot2 on its own is straightforward of course
/// assert_eq!(b"llo WorldHe", &rot2(b"Hello World".to_owned()));
///
/// // These operations can be conveniently used in a method chain
/// // by using the extension traits.
/// //
/// // This is also quite handy if you just need to
/// // modify a value in a long method chain.
/// //
/// // Here apply() also comes in quite handy, because we can use it
/// // to modify the value itself (turning it into a reference).
/// assert_eq!(b"llo_WorldHe",
///     b"Hello World"
///         .to_owned()
///         .sideeffect(|buf| count(&mut accu, buf, b'l'))
///         .mutating(|buf| replace(buf, b' ', b'_'))
///         .apply(rot2)
///         .borrow() as &[u8]);
/// assert_eq!(accu, 9);
///
/// // There is also the mutating_mut variant, which can operate on any mutable reference;
/// // this is mainly useful in a method chain if you are dealing with a mutable reference.
/// //
/// // This example is quite artificial though.
/// assert_eq!(b"llo_WorldHe",
///     b"hello world"
///         .to_owned()
///         .mutating(|buf|
///             // Can not use sideeffect_ref at the start, because it drops the mut reference
///             // status
///             buf.sideeffect_mut(|buf| count(&mut accu, buf, b'l'))
///                .mutating_mut(|buf| replace(buf, b' ', b'_'))
///                .mutating_mut(|buf| replace(buf, b'h', b'H'))
///                .mutating_mut(|buf| replace(buf, b'w', b'W'))
///                // Using rot2 is more complex now
///                .mutating_mut(|buf| {
///                  *buf = rot2(*buf);
///                })
///                // Can use sideeffect_ref at the end, because we no longer need
///                // the &mut reference
///                .sideeffect_ref(|buf| count(&mut accu, *buf, b'l'))
///                // And we can use apply to fix the return value – if we really want to go
///                // crazy and avoid using a {} block
///                .apply(|_| ())
///                // [crate::mem::DiscardResult::discard_result] does the same job and it is more explicit.
///                .discard_result())
///         .borrow() as &[u8]);
/// assert_eq!(accu, 15);
/// ```
pub fn mutating<T, F>(mut v: T, mut f: F) -> T
where
    F: FnMut(&mut T),
{
    f(&mut v);
    v
}

/// Mutating values on the fly in a method chain
pub trait MutatingExt {
    /// Mutating values on the fly in a method chain (owning)
    ///
    /// # Examples
    ///
    /// See [mutating].
    fn mutating<F>(self, f: F) -> Self
    where
        F: FnMut(&mut Self);

    /// Mutating values on the fly in a method chain (non-owning)
    ///
    /// # Examples
    ///
    /// See [mutating].
    fn mutating_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: FnMut(&mut Self);
}

impl<T> MutatingExt for T {
    fn mutating<F>(self, f: F) -> Self
    where
        F: FnMut(&mut Self),
    {
        mutating(self, f)
    }

    fn mutating_mut<F>(&mut self, mut f: F) -> &mut Self
    where
        F: FnMut(&mut Self),
    {
        f(self);
        self
    }
}

/// Apply a sideeffect using some value in an expression
///
/// # Examples
///
/// See [mutating].
pub fn sideeffect<T, F>(v: T, mut f: F) -> T
where
    F: FnMut(&T),
{
    f(&v);
    v
}

/// Apply sideeffect on the fly in a method chain
pub trait SideffectExt {
    /// Apply sideeffect on the fly in a method chain (owning)
    ///
    /// # Examples
    ///
    /// See [mutating].
    fn sideeffect<F>(self, f: F) -> Self
    where
        F: FnMut(&Self);
    /// Apply sideeffect on the fly in a method chain (immutable ref)
    ///
    /// # Examples
    ///
    /// See [mutating].
    fn sideeffect_ref<F>(&self, f: F) -> &Self
    where
        F: FnMut(&Self);
    /// Apply sideeffect on the fly in a method chain (mutable ref)
    ///
    /// # Examples
    ///
    /// See [mutating].
    fn sideeffect_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: FnMut(&Self);
}

impl<T> SideffectExt for T {
    fn sideeffect<F>(self, f: F) -> Self
    where
        F: FnMut(&Self),
    {
        sideeffect(self, f)
    }

    fn sideeffect_ref<F>(&self, mut f: F) -> &Self
    where
        F: FnMut(&Self),
    {
        f(self);
        self
    }

    fn sideeffect_mut<F>(&mut self, mut f: F) -> &mut Self
    where
        F: FnMut(&Self),
    {
        f(self);
        self
    }
}

/// Just run the function
///
/// This is occasionally useful; in particular, you can
/// use it to control the meaning of the question mark operator.
///
/// # Examples
///
/// ```
/// use rosenpass_util::functional::run;
///
/// fn add_and_mul(a: Option<u32>, b: Option<u32>, c: anyhow::Result<u32>, d: anyhow::Result<u32>) -> u32 {
///     run(|| -> anyhow::Result<u32> {
///         let ab = run(|| Some(a? * b?)).unwrap_or(0);
///         Ok(ab + c? + d?)
///     }).unwrap()
/// }
///
/// assert_eq!(98, add_and_mul(Some(10), Some(9), Ok(3), Ok(5)));
/// assert_eq!(8, add_and_mul(None, Some(15), Ok(3), Ok(5)));
/// ```
pub fn run<R, F: FnOnce() -> R>(f: F) -> R {
    f()
}

/// Apply a function to a value in a method chain
pub trait ApplyExt: Sized {
    /// Apply a function to a value in a method chain
    ///
    /// # Examples
    ///
    /// See [mutating].
    fn apply<R, F>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R;
}

impl<T: Sized> ApplyExt for T {
    fn apply<R, F>(self, f: F) -> R
    where
        F: FnOnce(Self) -> R,
    {
        f(self)
    }
}
