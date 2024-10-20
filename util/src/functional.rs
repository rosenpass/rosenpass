pub fn mutating<T, F>(mut v: T, f: F) -> T
where
    F: FnMut(&mut T),
{
    f(&mut v);
    v
}

pub trait MutatingExt {
    fn mutating<F>(self, f: F) -> Self
    where
        F: FnMut(&mut Self);
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

pub fn sideeffect<T, F>(v: T, mut f: F) -> T
where
    F: FnMut(&T),
{
    f(&v);
    v
}

pub trait SideffectExt {
    fn sideeffect<F>(self, f: F) -> Self
    where
        F: FnMut(&Self);
    fn sideeffect_ref<F>(&self, f: F) -> &Self
    where
        F: FnMut(&Self);
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

pub fn run<R, F: FnOnce() -> R>(f: F) -> R {
    f()
}

pub trait ApplyExt: Sized {
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
