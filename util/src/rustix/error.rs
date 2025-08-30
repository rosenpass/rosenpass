//! Rustix extensions for error handling

/// Provides access to the last system error number
///
/// > The integer variable errno is set by system calls and some library functions in the event of an error to indicate what went wrong.
///
/// -- `man 3 errno`
///
/// # Panics
///
/// This function panics if ther
///
/// # Examples
///
/// ```rust
///
/// use rustix::io::Errno as E;
/// use rosenpass_util::rustix::{errno, try_errno, last_os_result};
///
/// let res = unsafe { libc::mkdir(c"/tmp/baz".as_ptr(), 0) };
/// assert_eq!(res, -1);
/// assert_eq!(errno(), E::EXIST);
/// assert_eq!(try_errno(), Some(E::EXIST));
/// assert_eq!(last_os_result(), Err(E::EXIST));
///
/// // Deliberately clear the system error
/// unsafe { libc::__errno_location().write(0) };
/// // assert_eq!(errno(), _); // PANICS
/// assert_eq!(try_errno(), None);
/// assert_eq!(last_os_result(), Ok(()));
/// ```
///
/// Calling errno() when there is no error causes a panic:
///
/// ```rust,should_panic
///
/// use rustix::io::Errno as E;
/// use rosenpass_util::rustix::errno;
///
/// // Deliberately clear the system error
/// unsafe { libc::__errno_location().write(0) };
/// errno(); // PANICS
/// ```
pub fn errno() -> rustix::io::Errno {
    match try_errno() {
        None => panic!("Tried to retrieve last system error, but there was no system error (the system error number, errno = 0)"),
        Some(errno) => errno,
    }
}

/// Provides access to the last system error number.
///
/// Variant of [errno()] that will return None if there was no system error.
///
/// # Examples
///
/// See [errno()].
pub fn try_errno() -> Option<rustix::io::Errno> {
    let raw = unsafe { libc::__errno_location().read() };
    match raw {
        0 => None,
        _ => Some(rustix::io::Errno::from_raw_os_error(raw)),
    }
}

/// Provides access to the last system error number.
///
/// Variant of [errno()] that will return `Err(errno)` if there
/// was a system error and `Ok(())` otherwise.
///
/// # Examples
///
/// See [errno()].
pub fn last_os_result() -> Result<(), rustix::io::Errno> {
    match try_errno() {
        None => Ok(()),
        Some(errno) => Err(errno),
    }
}

/// Convert low level errors into std::io::Error
///
/// # Examples
///
/// ```
/// use std::io::ErrorKind as EK;
/// use rustix::io::Errno;
/// use rosenpass_util::rustix::IntoStdioErr;
///
/// let e = Errno::INTR.into_stdio_err();
/// assert!(matches!(e.kind(), EK::Interrupted));
///
/// let r : rustix::io::Result<()> = Err(Errno::INTR);
/// assert!(matches!(r, Err(e) if e.kind() == EK::Interrupted));
/// ```
pub trait IntoStdioErr {
    /// Target type produced (e.g. std::io:Error or std::io::Result depending on context
    type Target;
    /// Convert low level errors to
    fn into_stdio_err(self) -> Self::Target;
}

impl IntoStdioErr for rustix::io::Errno {
    type Target = std::io::Error;

    fn into_stdio_err(self) -> Self::Target {
        std::io::Error::from_raw_os_error(self.raw_os_error())
    }
}

impl<T> IntoStdioErr for rustix::io::Result<T> {
    type Target = std::io::Result<T>;

    fn into_stdio_err(self) -> Self::Target {
        self.map_err(IntoStdioErr::into_stdio_err)
    }
}
