use crate::To;
use std::marker::PhantomData;

struct ToClosure<Dst, Ret, Fun>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    fun: Fun,
    _val: PhantomData<Box<Dst>>,
}

impl<Dst, Ret, Fun> To<Dst, Ret> for ToClosure<Dst, Ret, Fun>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    fn to(self, out: &mut Dst) -> Ret {
        (self.fun)(out)
    }
}

/// Used to create a function with destination.
///
/// See the tutorial in [readme.me]..
pub fn with_destination<Dst, Ret, Fun>(fun: Fun) -> impl To<Dst, Ret>
where
    Dst: ?Sized,
    Fun: FnOnce(&mut Dst) -> Ret,
{
    ToClosure {
        fun,
        _val: PhantomData,
    }
}
