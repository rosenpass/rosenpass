use crate::{Beside, CondenseBeside};
use std::borrow::BorrowMut;

/// The To trait is the core of the to crate; most functions with destinations will either return
/// an object that is an instance of this trait or they will return `-> impl To<Destination,
/// Return_value`.
///
/// A quick way to implement a function with destination is to use the
/// [with_destination(|param: &mut Type| ...)] higher order function.
pub trait To<Dst: ?Sized, Ret>: Sized {
    /// Writes self to the destination `out` and returns a value of type `Ret`.
    ///
    /// This is the core method that must be implemented by all types implementing `To`.
    fn to(self, out: &mut Dst) -> Ret;

    /// Generate a destination on the fly with a lambda.
    ///
    /// Calls the provided closure to create a value,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    fn to_this_beside<Val, Fun>(self, fun: Fun) -> Beside<Val, Ret>
    where
        Val: BorrowMut<Dst>,
        Fun: FnOnce() -> Val,
    {
        let mut val = fun();
        let ret = self.to(val.borrow_mut());
        Beside(val, ret)
    }

    /// Generate a destination on the fly using default.
    ///
    /// Uses [Default] to create a value,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    fn to_value_beside(self) -> Beside<Dst, Ret>
    where
        Dst: Sized + Default,
    {
        self.to_this_beside(|| Dst::default())
    }

    /// Generate a destination on the fly using default and a custom storage type.
    ///
    /// Uses [Default] to create a value of the given type,
    /// calls [crate::to()] to evaluate the function and finally
    /// returns a [Beside] instance containing the generated destination value and the return
    /// value.
    ///
    /// Using collect_beside with an explicit type instead of [Self::to_value_beside] is mainly useful
    /// when the Destination is unsized.
    ///
    /// This could be the case when the destination is an `[u8]` for instance.
    fn collect_beside<Val>(self) -> Beside<Val, Ret>
    where
        Val: Default + BorrowMut<Dst>,
    {
        self.to_this_beside(|| Val::default())
    }

    /// Generate a destination on the fly with a lambda, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::to_this_beside] followed by calling [Beside::condense].
    fn to_this<Val, Fun>(self, fun: Fun) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Ret: CondenseBeside<Val>,
        Val: BorrowMut<Dst>,
        Fun: FnOnce() -> Val,
    {
        self.to_this_beside(fun).condense()
    }

    /// Generate a destination on the fly using default, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::to_value_beside] followed by calling [Beside::condense].
    fn to_value(self) -> <Ret as CondenseBeside<Dst>>::Condensed
    where
        Dst: Sized + Default,
        Ret: CondenseBeside<Dst>,
    {
        self.to_value_beside().condense()
    }

    /// Generate a destination on the fly using default, condensing the destination and the
    /// return value into one.
    ///
    /// This is like using [Self::collect_beside] followed by calling [Beside::condense].
    fn collect<Val>(self) -> <Ret as CondenseBeside<Val>>::Condensed
    where
        Val: Default + BorrowMut<Dst>,
        Ret: CondenseBeside<Val>,
    {
        self.collect_beside::<Val>().condense()
    }
}
