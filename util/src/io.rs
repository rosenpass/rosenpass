use std::{borrow::Borrow, io};

use anyhow::ensure;

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

pub trait SubstituteForIoErrorKindExt<T>: Sized {
    type Error;
    fn substitute_for_ioerr_kind_with<F: FnOnce() -> T>(
        self,
        kind: io::ErrorKind,
        f: F,
    ) -> Result<T, Self::Error>;
    fn substitute_for_ioerr_kind(self, kind: io::ErrorKind, v: T) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_kind_with(kind, || v)
    }

    fn substitute_for_ioerr_interrupted_with<F: FnOnce() -> T>(
        self,
        f: F,
    ) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_kind_with(io::ErrorKind::Interrupted, f)
    }

    fn substitute_for_ioerr_interrupted(self, v: T) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_interrupted_with(|| v)
    }

    fn substitute_for_ioerr_wouldblock_with<F: FnOnce() -> T>(
        self,
        f: F,
    ) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_kind_with(io::ErrorKind::WouldBlock, f)
    }

    fn substitute_for_ioerr_wouldblock(self, v: T) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_wouldblock_with(|| v)
    }
}

impl<T, E: TryIoErrorKind> SubstituteForIoErrorKindExt<T> for Result<T, E> {
    type Error = E;

    fn substitute_for_ioerr_kind_with<F: FnOnce() -> T>(
        self,
        kind: io::ErrorKind,
        f: F,
    ) -> Result<T, Self::Error> {
        match self.try_io_err_kind_hint() {
            Ok(v) => Ok(v),
            Err((_, Some(k))) if k == kind => Ok(f()),
            Err((e, _)) => Err(e),
        }
    }
}

/// Automatically handles `std::io::ErrorKind::Interrupted`.
///
/// - If there is no error (i.e. on `Ok(r)`), the function will return `Ok(Some(r))`
/// - `Interrupted` is handled internally, by retrying the IO operation
/// - Other errors are returned as is
pub fn handle_interrupted<R, E, F>(mut iofn: F) -> Result<Option<R>, E>
where
    E: TryIoErrorKind,
    F: FnMut() -> Result<R, E>,
{
    use io::ErrorKind as E;
    loop {
        match iofn().try_io_err_kind_hint() {
            Ok(v) => return Ok(Some(v)),
            Err((_, Some(E::Interrupted))) => continue, // try again
            Err((e, _)) => return Err(e),
        };
    }
}

/// Automatically handles `std::io::ErrorKind::{WouldBlock, Interrupted}`.
///
/// - If there is no error (i.e. on `Ok(r)`), the function will return `Ok(Some(r))`
/// - `Interrupted` is handled internally, by retrying the IO operation
/// - `WouldBlock` is handled by returning `Ok(None)`,
/// - Other errors are returned as is
pub fn nonblocking_handle_io_errors<R, E, F>(mut iofn: F) -> Result<Option<R>, E>
where
    E: TryIoErrorKind,
    F: FnMut() -> Result<R, E>,
{
    use io::ErrorKind as E;
    loop {
        match iofn().try_io_err_kind_hint() {
            Ok(v) => return Ok(Some(v)),
            Err((_, Some(E::WouldBlock))) => return Ok(None), // no data to read
            Err((_, Some(E::Interrupted))) => continue,       // try again
            Err((e, _)) => return Err(e),
        };
    }
}

pub trait ReadNonblockingWithBoringErrorsHandledExt {
    /// Convenience wrapper using [nonblocking_handle_io_errors] with [std::io::Read]
    fn read_nonblocking_with_boring_errors_handled(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<usize>>;
}

impl<T: io::Read> ReadNonblockingWithBoringErrorsHandledExt for T {
    fn read_nonblocking_with_boring_errors_handled(
        &mut self,
        buf: &mut [u8],
    ) -> io::Result<Option<usize>> {
        nonblocking_handle_io_errors(|| self.read(buf))
    }
}

pub trait ReadExt {
    fn read_exact_til_end(&mut self, buf: &mut [u8]) -> anyhow::Result<()>;
}

impl<T> ReadExt for T
where
    T: std::io::Read,
{
    fn read_exact_til_end(&mut self, buf: &mut [u8]) -> anyhow::Result<()> {
        self.read_exact(buf)?;
        ensure!(
            self.read(&mut [0u8; 8])? == 0,
            "Read source longer than buffer"
        );
        Ok(())
    }
}
