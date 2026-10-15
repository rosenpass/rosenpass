//! Rustix extensions for error handling

/// Provides access to the last system error number
///
/// > The integer variable errno is set by system calls and some library functions in the event of an error to indicate what went wrong.
///
/// -- `man 3 errno`
///
/// # Panics
///
/// This function panics if there is no system error to retrieve
/// (the system error number, errno = 0).
///
/// # Examples
///
#[cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
///
/// use rustix::io::Errno as E;
/// use rosenpass::internal::util::rustix::{errno, try_errno, last_os_result};
///
/// // Open a path below /dev/null; /dev/null is a character device, not a
/// // directory, so this reliably fails with ENOTDIR on any system and,
/// // being a read-only open, has no side effects.
/// let res = unsafe { libc::open(c"/dev/null/rosenpass-errno-doctest".as_ptr(), libc::O_RDONLY) };
/// assert_eq!(res, -1);
/// assert_eq!(errno(), E::NOTDIR);
/// assert_eq!(try_errno(), Some(E::NOTDIR));
/// assert_eq!(last_os_result(), Err(E::NOTDIR));
///
/// // On common libc implementations (glibc, musl), a freshly spawned thread
/// // starts out with errno = 0, so there is no system error to retrieve in it
/// std::thread::spawn(|| {
///     // assert_eq!(errno(), _); // PANICS
///     assert_eq!(try_errno(), None);
///     assert_eq!(last_os_result(), Ok(()));
/// })
/// .join()
/// .unwrap();
/// ```
///
/// Calling errno() when there is no error causes a panic:
///
#[cfg_attr(feature = "expose_internal_modules", doc = "```rust,should_panic")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
///
/// use rosenpass::internal::util::rustix::errno;
///
/// // On common libc implementations (glibc, musl), a freshly spawned thread starts out with errno = 0
/// std::thread::spawn(|| {
///     errno(); // PANICS
/// })
/// .join()
/// .unwrap(); // Propagate the panic to this thread
/// ```
pub fn errno() -> rustix::io::Errno {
    match try_errno() {
        None => panic!(
            "Tried to retrieve last system error, but there was no system error (the system error number, errno = 0)"
        ),
        Some(errno) => errno,
    }
}

/// Provides access to the last system error number.
///
/// Variant of [errno()] that will return None if there was no system error.
///
/// This reads errno through [std::io::Error::last_os_error], which retrieves
/// errno portably on every platform supported by the Rust standard library.
///
/// # Examples
///
/// See [errno()].
pub fn try_errno() -> Option<rustix::io::Errno> {
    let raw = std::io::Error::last_os_error().raw_os_error()?;
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
/// # Sticky errno convention
///
/// Errno is only meaningful immediately after a system call (or libc
/// function) has actually failed: failing calls set errno, but successful
/// calls do not reset the value, so errno can not be used to check whether
/// an error occurred in the first place; only the function return value can
/// answer this question.
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
#[cfg_attr(feature = "expose_internal_modules", doc = "```")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
/// use std::io::ErrorKind as EK;
/// use rustix::io::Errno;
/// use rosenpass::internal::util::rustix::IntoStdioErr;
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
