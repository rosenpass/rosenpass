/// Beside condensation.
///
/// This trait can be used to enable the use of [to_this(|| ...)](crate::To::to_this),
/// [to_value()](crate::To::to_value), and [collect::<...>()](crate::To::collect) with custom
/// types.
///
/// The function [Beside::condense()](crate::Beside::condense) is a shorthand for using the
/// condense trait.
pub trait CondenseBeside<Val> {
    type Condensed;

    fn condense(self, ret: Val) -> Self::Condensed;
}

impl<Val> CondenseBeside<Val> for () {
    type Condensed = Val;

    fn condense(self, ret: Val) -> Val {
        ret
    }
}

impl<Val, Error> CondenseBeside<Val> for Result<(), Error> {
    type Condensed = Result<Val, Error>;

    fn condense(self, ret: Val) -> Result<Val, Error> {
        self.map(|()| ret)
    }
}

impl<Val> CondenseBeside<Val> for Option<()> {
    type Condensed = Option<Val>;

    fn condense(self, ret: Val) -> Option<Val> {
        self.map(|()| ret)
    }
}
