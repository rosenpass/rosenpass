use std::{borrow::Borrow, io};

pub trait IoErrorKind {
    fn io_error_kind(&self) -> io::ErrorKind;
}

impl<T: Borrow<io::Error>> IoErrorKind for T {
    fn io_error_kind(&self) -> io::ErrorKind {
        self.borrow().kind()
    }
}

pub trait TryIoErrorKind {
    fn try_io_error_kind(&self) -> Option<io::ErrorKind>;
}

impl<T: IoErrorKind> TryIoErrorKind for T {
    fn try_io_error_kind(&self) -> Option<io::ErrorKind> {
        Some(self.io_error_kind())
    }
}

pub trait IoResultKindHintExt<T>: Sized {
    type Error;
    fn io_err_kind_hint(self) -> Result<T, (Self::Error, io::ErrorKind)>;
}

impl<T, E: IoErrorKind> IoResultKindHintExt<T> for Result<T, E> {
    type Error = E;
    fn io_err_kind_hint(self) -> Result<T, (E, io::ErrorKind)> {
        self.map_err(|e| {
            let kind = e.borrow().io_error_kind();
            (e, kind)
        })
    }
}

pub trait TryIoResultKindHintExt<T>: Sized {
    type Error;
    fn try_io_err_kind_hint(self) -> Result<T, (Self::Error, Option<io::ErrorKind>)>;
}

impl<T, E: TryIoErrorKind> TryIoResultKindHintExt<T> for Result<T, E> {
    type Error = E;
    fn try_io_err_kind_hint(self) -> Result<T, (E, Option<io::ErrorKind>)> {
        self.map_err(|e| {
            let opt_kind = e.borrow().try_io_error_kind();
            (e, opt_kind)
        })
    }
}
