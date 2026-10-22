//! Helpers for performing system calls

use std::os::fd::FromRawFd;

use super::try_errno;

/// Wrapper type around [libc::c_long] that indicates that this value represents
/// the result of a system call
///
/// # Return value convention
///
/// This type expects the libc (errno global variable) convention for
/// system call return values. In case of an error, the wrapper returns `-1`
/// and stores the error code in the thread-local errno variable. In case of
/// success, it returns the system call's (non-negative) return value as is.
///
/// This convention is not used by the kernel syscall functionality itself; when
/// syscalls are issued, the kernel returns error codes as distinct negative values
/// in the range `-4095..=-1`, so errno is purely a libc convention, which we
/// nonetheless implement here.
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyscallResult(pub libc::c_long);

impl SyscallResult {
    /// Access to [Self::0]
    pub fn raw_value(&self) -> libc::c_long {
        self.0
    }

    /// Claim the system call result as a file descriptor
    ///
    /// - If [Self::raw_value] < 0, then [try_errno()] is called to retrieve
    ///   the error type; if no error number is available (errno = 0), the
    ///   libc return-value convention documented on [SyscallResult] has been
    ///   violated — e.g. a raw kernel result was fed in by mistake — which
    ///   is a bug in the caller, so this function panics
    /// - If [Self::raw_value] > [i32::MAX], panics
    /// - Otherwise, this just forwards to [rustix::fd::OwnedFd::from_raw_fd]
    ///
    /// # Panic
    ///
    /// Panics if [Self::raw_value] > [i32::MAX], or if [Self::raw_value] < 0
    /// but no error number is available (errno = 0), which violates the libc
    /// return-value convention documented on [SyscallResult].
    ///
    /// # Safety
    ///
    /// Refer to [rustix::fd::OwnedFd::from_raw_fd].
    pub unsafe fn claim_fd(&self) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
        let fde = self.0;
        match fde {
            e if e < 0 => Err(try_errno().expect(
                "system call returned an error result but no error number is set (errno = 0)",
            )),
            fd if fd > i32::MAX.into() => panic!("File descriptor `{fd}` is out of bounds!"),
            fd => Ok(unsafe { rustix::fd::OwnedFd::from_raw_fd(fd as i32) }),
        }
    }
}

impl From<libc::c_long> for SyscallResult {
    fn from(value: libc::c_long) -> Self {
        Self(value)
    }
}
