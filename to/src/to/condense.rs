//! This module provides condensation for values that stand side by side,
//! which is often useful when working with destination parameters. See [CondenseBeside]
//! for more details.

/// Condenses two values that stand beside each other into one value.
/// For example, a blanked implementation for [Result<(), Error>](Result) is provided. If
/// `condense(val)` is called on such an object, a [Result<Val, Error>](Result) will
/// be returned, if `val` is of type `Val`.
///
/// This trait can be used to enable the use of [to_this(|| ...)](crate::To::to_this),
/// [to_value()](crate::To::to_value), and [collect::<...>()](crate::To::collect) with custom
/// types.
///
/// The function [Beside::condense()](crate::Beside::condense) is a shorthand for using the
/// condense trait.
///
/// # Example
/// As an example implementation, we take a look at the blanket implementation for [Option]
/// ```ignore
/// impl<Val> CondenseBeside<Val> for Option<()> {
///     type Condensed = Option<Val>;
///
///     /// Replaces the empty tuple inside this [Option] with `ret`.
///     fn condense(self, ret: Val) -> Option<Val> {
///         self.map(|()| ret)
///     }
/// }
/// ```
pub trait CondenseBeside<Val> {
    /// The type that results from condensation.
    type Condensed;

    /// Takes ownership of `self` and condenses it with the given value.
    fn condense(self, ret: Val) -> Self::Condensed;
}

impl<Val> CondenseBeside<Val> for () {
    type Condensed = Val;

    /// Replaces this empty tuple with `ret`.
    fn condense(self, ret: Val) -> Val {
        ret
    }
}

impl<Val, Error> CondenseBeside<Val> for Result<(), Error> {
    type Condensed = Result<Val, Error>;

    /// Replaces the empty tuple inside this [Result] with `ret`.
    fn condense(self, ret: Val) -> Result<Val, Error> {
        self.map(|()| ret)
    }
}

impl<Val> CondenseBeside<Val> for Option<()> {
    type Condensed = Option<Val>;

    /// Replaces the empty tuple inside this [Option] with `ret`.
    fn condense(self, ret: Val) -> Option<Val> {
        self.map(|()| ret)
    }
}
