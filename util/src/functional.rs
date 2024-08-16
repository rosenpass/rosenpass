pub fn mutating<T, F>(mut v: T, f: F) -> T
where
    F: Fn(&mut T),
{
    f(&mut v);
    v
}

pub trait MutatingExt {
    fn mutating<F>(self, f: F) -> Self
    where
        F: Fn(&mut Self);
    fn mutating_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&mut Self);
}

impl<T> MutatingExt for T {
    fn mutating<F>(self, f: F) -> Self
    where
        F: Fn(&mut Self),
    {
        mutating(self, f)
    }

    fn mutating_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&mut Self),
    {
        f(self);
        self
    }
}

pub fn sideeffect<T, F>(v: T, f: F) -> T
where
    F: Fn(&T),
{
    f(&v);
    v
}

pub trait SideffectExt {
    fn sideeffect<F>(self, f: F) -> Self
    where
        F: Fn(&Self);
    fn sideeffect_ref<F>(&self, f: F) -> &Self
    where
        F: Fn(&Self);
    fn sideeffect_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&Self);
}

impl<T> SideffectExt for T {
    fn sideeffect<F>(self, f: F) -> Self
    where
        F: Fn(&Self),
    {
        sideeffect(self, f)
    }

    fn sideeffect_ref<F>(&self, f: F) -> &Self
    where
        F: Fn(&Self),
    {
        f(self);
        self
    }

    fn sideeffect_mut<F>(&mut self, f: F) -> &mut Self
    where
        F: Fn(&Self),
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
