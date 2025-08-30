//! Rustix extensions for error handling

use anyhow::bail;
use rustix::io::fcntl_dupfd_cloexec;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::{mem::Forgetting, result::OkExt};

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
