pub fn mutating<T, F>(mut v: T, f: F) -> T
where
    F: Fn(&mut T),
{
    f(&mut v);
    v
}

pub fn sideeffect<T, F>(v: T, f: F) -> T
where
    F: Fn(&T),
{
    f(&v);
    v
}

pub fn run<R, F: FnOnce() -> R>(f: F) -> R {
    f()
}
