//! Helpers for performing IO
//!
//! # IO Error handling helpers tutorial
//!
//! ```
//! use std::io::ErrorKind as EK;
//!
//! // It can be a bit hard to use IO errors in match statements
//!
//! fn io_placeholder() -> std::io::Result<()> {
//!     Ok(())
//! }
//!
//! loop {
//!     match io_placeholder() {
//!         Ok(()) => break,
//!         // All errors are unreachable; just here for demo purposes
//!         Err(e) if e.kind() == EK::Interrupted => continue,
//!         Err(e) if e.kind() == EK::WouldBlock => {
//!             panic!("This particular function is not designed to be used in nonblocking code!");
//!         }
//!         Err(e) => Err(e)?,
//!     }
//! }
//!
//! // For this reason this module contains various helper functions to make
//! // matching on error kinds a bit less repetitive. [IoResultKindHintExt::io_err_kind_hint]
//! // provides the basic functionality for use mostly with std::io::Result
//!
//! use rosenpass_util::io::IoResultKindHintExt;
//!
//! loop {
//!     match io_placeholder().io_err_kind_hint() {
//!         Ok(()) => break,
//!         // All errors are unreachable; just here for demo purposes
//!         Err((_, EK::Interrupted)) => continue,
//!         Err((_, EK::WouldBlock)) => {
//!             // Unreachable, just here for explanation purposes
//!             panic!("This particular function is not designed to be used in nonblocking code!");
//!         }
//!         Err((e, _)) => Err(e)?,
//!     }
//! }
//!
//! // The trait can be customized; firstly, you can use IoErrorKind
//! // for error types that can be fully represented as std::io::ErrorKind
//!
//! use rosenpass_util::io::IoErrorKind;
//!
//! #[derive(thiserror::Error, Debug, PartialEq, Eq)]
//! enum MyErrno {
//!     #[error("Got interrupted")]
//!     Interrupted,
//!     #[error("In nonblocking mode")]
//!     WouldBlock,
//! }
//!
//! impl IoErrorKind for MyErrno {
//!     fn io_error_kind(&self) -> std::io::ErrorKind {
//!         use MyErrno as ME;
//!         match self {
//!             ME::Interrupted => EK::Interrupted,
//!             ME::WouldBlock => EK::WouldBlock,
//!         }
//!     }
//! }
//!
//! assert_eq!(
//!     EK::Interrupted,
//!     std::io::Error::new(EK::Interrupted, "artificially interrupted").io_error_kind()
//! );
//! assert_eq!(EK::Interrupted, MyErrno::Interrupted.io_error_kind());
//! assert_eq!(EK::WouldBlock, MyErrno::WouldBlock.io_error_kind());
//!
//! // And when an error can not fully be represented as an std::io::ErrorKind,
//! // you can still use [TryIoErrorKind]
//!
//! use rosenpass_util::io::TryIoErrorKind;
//!
//! #[derive(thiserror::Error, Debug, PartialEq, Eq)]
//! enum MyErrnoOrBlue {
//!     #[error("Got interrupted")]
//!     Interrupted,
//!     #[error("In nonblocking mode")]
//!     WouldBlock,
//!     #[error("I am feeling blue")]
//!     FeelingBlue,
//! }
//!
//! impl TryIoErrorKind for MyErrnoOrBlue {
//!     fn try_io_error_kind(&self) -> Option<std::io::ErrorKind> {
//!         use MyErrnoOrBlue as ME;
//!         match self {
//!             ME::Interrupted => Some(EK::Interrupted),
//!             ME::WouldBlock => Some(EK::WouldBlock),
//!             ME::FeelingBlue => None,
//!         }
//!     }
//! }
//!
//! assert_eq!(
//!     Some(EK::Interrupted),
//!     MyErrnoOrBlue::Interrupted.try_io_error_kind()
//! );
//! assert_eq!(
//!     Some(EK::WouldBlock),
//!     MyErrnoOrBlue::WouldBlock.try_io_error_kind()
//! );
//! assert_eq!(None, MyErrnoOrBlue::FeelingBlue.try_io_error_kind());
//!
//! // TryIoErrorKind is automatically implemented for all types that implement
//! // IoErrorKind
//!
//! assert_eq!(
//!     Some(EK::Interrupted),
//!     std::io::Error::new(EK::Interrupted, "artificially interrupted").try_io_error_kind()
//! );
//! assert_eq!(
//!     Some(EK::Interrupted),
//!     MyErrno::Interrupted.try_io_error_kind()
//! );
//! assert_eq!(
//!     Some(EK::WouldBlock),
//!     MyErrno::WouldBlock.try_io_error_kind()
//! );
//!
//! // By implementing IoErrorKind, we can automatically make use of IoResultKindHintExt<T>
//! // with our custom error type
//!
//! //use rosenpass_util::io::IoResultKindHintExt;
//!
//! assert_eq!(
//!     Ok::<_, MyErrno>(42).io_err_kind_hint(),
//!     Ok(42));
//! assert!(matches!(
//!     Err::<(), _>(std::io::Error::new(EK::Interrupted, "artificially interrupted")).io_err_kind_hint(),
//!     Err((err, EK::Interrupted)) if format!("{err:?}") == "Custom { kind: Interrupted, error: \"artificially interrupted\" }"));
//! assert_eq!(
//!     Err::<(), _>(MyErrno::Interrupted).io_err_kind_hint(),
//!     Err((MyErrno::Interrupted, EK::Interrupted)));
//!
//! // Correspondingly, TryIoResultKindHintExt can be used for Results with Errors
//! // that implement TryIoErrorKind
//!
//! use crate::rosenpass_util::io::TryIoResultKindHintExt;
//!
//! assert_eq!(
//!     Ok::<_, MyErrnoOrBlue>(42).try_io_err_kind_hint(),
//!     Ok(42));
//! assert_eq!(
//!     Err::<(), _>(MyErrnoOrBlue::Interrupted).try_io_err_kind_hint(),
//!     Err((MyErrnoOrBlue::Interrupted, Some(EK::Interrupted))));
//! assert_eq!(
//!     Err::<(), _>(MyErrnoOrBlue::FeelingBlue).try_io_err_kind_hint(),
//!     Err((MyErrnoOrBlue::FeelingBlue, None)));
//!
//! // SubstituteForIoErrorKindExt serves as a helper to handle specific ErrorKinds
//! // using a method chaining style. It works on anything that implements TryIoErrorKind.
//!
//! use rosenpass_util::io::SubstituteForIoErrorKindExt;
//!
//! assert_eq!(Ok(42),
//!     Err(MyErrnoOrBlue::Interrupted)
//!         .substitute_for_ioerr_kind_with(EK::Interrupted, || 42));
//!
//! assert_eq!(Err(MyErrnoOrBlue::WouldBlock),
//!     Err(MyErrnoOrBlue::WouldBlock)
//!         .substitute_for_ioerr_kind_with(EK::Interrupted, || 42));
//!
//! // The other functions in SubstituteForIoErrorKindExt are mostly just wrappers,
//! // getting the same job done with minor convenience
//!
//! // Plain Ok() value instead of function
//! assert_eq!(Ok(42),
//!     Err(MyErrnoOrBlue::Interrupted)
//!         .substitute_for_ioerr_kind(EK::Interrupted, 42));
//! assert_eq!(Err(MyErrnoOrBlue::WouldBlock),
//!     Err(MyErrnoOrBlue::WouldBlock)
//!         .substitute_for_ioerr_kind(EK::Interrupted, 42));
//!
//! // For specific errors
//! assert_eq!(Ok(42),
//!     Err(MyErrnoOrBlue::Interrupted)
//!         .substitute_for_ioerr_interrupted_with(|| 42)
//!         .substitute_for_ioerr_wouldblock_with(|| 23));
//! assert_eq!(Ok(23),
//!     Err(MyErrnoOrBlue::WouldBlock)
//!         .substitute_for_ioerr_interrupted_with(|| 42)
//!         .substitute_for_ioerr_wouldblock_with(|| 23));
//! assert_eq!(Err(MyErrnoOrBlue::FeelingBlue),
//!     Err(MyErrnoOrBlue::FeelingBlue)
//!         .substitute_for_ioerr_interrupted_with(|| 42)
//!         .substitute_for_ioerr_wouldblock_with(|| 23));
//!
//! // And for specific errors without the function call
//! assert_eq!(Ok(42),
//!     Err(MyErrnoOrBlue::Interrupted)
//!         .substitute_for_ioerr_interrupted(42)
//!         .substitute_for_ioerr_wouldblock(23));
//! assert_eq!(Ok(23),
//!     Err(MyErrnoOrBlue::WouldBlock)
//!         .substitute_for_ioerr_interrupted(42)
//!         .substitute_for_ioerr_wouldblock(23));
//! assert_eq!(Err(MyErrnoOrBlue::FeelingBlue),
//!     Err(MyErrnoOrBlue::FeelingBlue)
//!         .substitute_for_ioerr_interrupted(42)
//!         .substitute_for_ioerr_wouldblock(23));
//!
//! // handle_interrupted automates the process of handling ErrorKind::Interrupted
//! // in cases where the action should simply be rerun; it can handle any error type
//! // that implements TryIoErrorKind. It lets other errors and Ok(_) pass through.
//!
//! use rosenpass_util::io::handle_interrupted;
//!
//! let mut ctr = 0u32;
//! let mut simulate_io = || -> Result<u32, MyErrnoOrBlue> {
//!     let r = match ctr % 6 {
//!         1 => Ok(42),
//!         3 => Err(MyErrnoOrBlue::FeelingBlue),
//!         5 => Err(MyErrnoOrBlue::WouldBlock),
//!         _ => Err(MyErrnoOrBlue::Interrupted),
//!     };
//!     ctr += 1;
//!     r
//! };
//!
//! assert_eq!(Ok(Some(42)), handle_interrupted(&mut simulate_io));
//! assert_eq!(Err(MyErrnoOrBlue::FeelingBlue), handle_interrupted(&mut simulate_io));
//! assert_eq!(Err(MyErrnoOrBlue::WouldBlock), handle_interrupted(&mut simulate_io));
//! // never returns None
//!
//! // nonblocking_handle_io_errors performs the same job, except that
//! // WouldBlock is substituted with Ok(None)
//!
//! use rosenpass_util::io::nonblocking_handle_io_errors;
//!
//! assert_eq!(Ok(Some(42)), nonblocking_handle_io_errors(&mut simulate_io));
//! assert_eq!(Err(MyErrnoOrBlue::FeelingBlue), nonblocking_handle_io_errors(&mut simulate_io));
//! assert_eq!(Ok(None), nonblocking_handle_io_errors(&mut simulate_io));
//!
//! Ok::<_, anyhow::Error>(())
//! ```

use std::{borrow::Borrow, io};
use std::io::Read;
use anyhow::ensure;
use rosenpass_to::{with_destination, To};

/// Generic trait for accessing [std::io::Error::kind]
///
/// # Examples
///
/// See [tutorial in the module](self).
pub trait IoErrorKind {
    /// Conversion to [std::io::Error::kind]
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn io_error_kind(&self) -> io::ErrorKind;
}

impl<T: Borrow<io::Error>> IoErrorKind for T {
    fn io_error_kind(&self) -> io::ErrorKind {
        self.borrow().kind()
    }
}

/// Generic trait for accessing [std::io::Error::kind] where it may not be present
///
/// # Examples
///
/// See [tutorial in the module](self).
pub trait TryIoErrorKind {
    /// Conversion to [std::io::Error::kind] where it may not be present
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn try_io_error_kind(&self) -> Option<io::ErrorKind>;
}

impl<T: IoErrorKind> TryIoErrorKind for T {
    fn try_io_error_kind(&self) -> Option<io::ErrorKind> {
        Some(self.io_error_kind())
    }
}

/// Helper for accessing [std::io::Error::kind] in Results
///
/// # Examples
///
/// See [tutorial in the module](self).
pub trait IoResultKindHintExt<T>: Sized {
    /// Error type including the ErrorKind hint
    type Error;
    /// Helper for accessing [std::io::Error::kind] in Results
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
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

/// Helper for accessing [std::io::Error::kind] in Results where it may not be present
///
/// # Examples
///
/// See [tutorial in the module](self).
pub trait TryIoResultKindHintExt<T>: Sized {
    /// Error type including the ErrorKind hint
    type Error;
    /// Helper for accessing [std::io::Error::kind] in Results where it may not be present
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
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

/// Helper for working with IO results using a method chaining style
///
/// # Examples
///
/// See [tutorial in the module](self).
pub trait SubstituteForIoErrorKindExt<T>: Sized {
    /// Error type produced by methods in this trait
    type Error;

    /// Substitute errors with a certain [std::io::ErrorKind] by a value produced by a function
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn substitute_for_ioerr_kind_with<F: FnOnce() -> T>(
        self,
        kind: io::ErrorKind,
        f: F,
    ) -> Result<T, Self::Error>;

    /// Substitute errors with a certain [std::io::ErrorKind] by a value
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn substitute_for_ioerr_kind(self, kind: io::ErrorKind, v: T) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_kind_with(kind, || v)
    }

    /// Substitute errors with [std::io::ErrorKind] [std::io::ErrorKind::Interrupted] by a value
    /// produced by a function
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn substitute_for_ioerr_interrupted_with<F: FnOnce() -> T>(
        self,
        f: F,
    ) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_kind_with(io::ErrorKind::Interrupted, f)
    }

    /// Substitute errors with [std::io::ErrorKind] [std::io::ErrorKind::Interrupted] by a value
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn substitute_for_ioerr_interrupted(self, v: T) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_interrupted_with(|| v)
    }

    /// Substitute errors with [std::io::ErrorKind] [std::io::ErrorKind::WouldBlock] by a value
    /// produced by a function
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
    fn substitute_for_ioerr_wouldblock_with<F: FnOnce() -> T>(
        self,
        f: F,
    ) -> Result<T, Self::Error> {
        self.substitute_for_ioerr_kind_with(io::ErrorKind::WouldBlock, f)
    }

    /// Substitute errors with [std::io::ErrorKind] [std::io::ErrorKind::WouldBlock] by a value
    ///
    /// # Examples
    ///
    /// See [tutorial in the module](self).
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
///
/// # Examples
///
/// See [tutorial in the module](self).
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
///
/// # Examples
///
/// See [tutorial in the module](self).
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

/// [std:io::Read] extension trait for call with [nonblocking_handle_io_errors] applied
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

/// Extension trait for [std::io::Read] providing the ability to read
/// a buffer exactly
pub trait ReadExt {
    /// Version of [std::io::Read::read_exact] that throws if there
    /// is extra data in the stream to be read
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::io::ReadExt;
    ///
    /// let mut buf = [0u8; 4];
    ///
    /// // Over or underlong buffer yields error
    /// assert!(b"12345".as_slice().read_exact_til_end(&mut buf).is_err());
    /// assert!(b"123".as_slice().read_exact_til_end(&mut buf).is_err());
    ///
    /// // Buffer of precisely the right length leads to successful read
    /// assert!(b"1234".as_slice().read_exact_til_end(&mut buf).is_ok());
    /// assert_eq!(b"1234", &buf);
    /// ```
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

/// Trait with methods to read until the end of the stream
pub trait ReadExactTilEnd: Read {
    /// Read exactly the number of bytes in `buf` from this reader, failing if EOF is encountered 
    /// before the buffer is filled or if there is more data in the reader after the buffer is filled.
    ///
    /// # Examples
    /// ```
    /// # use rosenpass_util::io::ReadExactTilEnd;
    /// # use std::io::Cursor;
    /// let mut buf = [0u8; 4];
    /// assert!(b"12345".as_slice().read_exact_til_end().to(&mut buf).is_err());
    /// assert!(b"123".as_slice().read_exact_til_end().to(&mut buf).is_err());
    /// assert!(b"1234".as_slice().read_exact_til_end().to(&mut buf).is_ok());
    /// ```
    fn read_exact_til_end(&mut self) -> impl To<[u8], anyhow::Result<()>>;
}

impl<T: Read> ReadExactTilEnd for T {
    fn read_exact_til_end(&mut self) -> impl To<[u8], anyhow::Result<()>> {
        with_destination(move |buf: &mut [u8]| {
            self.read_exact(buf)?;
            anyhow::ensure!(
                self.read(&mut [0u8; 8])? == 0,
                "Found trailing data after reading whole buffer"
            );
            Ok(())
        })
    }
}
