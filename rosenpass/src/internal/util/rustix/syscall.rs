//! Helpers for performing system calls

use std::os::fd::FromRawFd;

use num_traits::Signed;

use crate::internal::util::functional::ApplyExt;

use super::try_errno;

/// Wrapper type around a raw system call return value
///
/// # Return value convention
///
/// This type expects the libc (errno global variable) convention for
/// system call return values. In case of an error, the system call returns
/// a negative value (usually `-1`) and libc stores the error code in the
/// thread-local errno variable. In case of success, it returns the system
/// call's (non-negative) return value as is.
///
/// This convention is not used by the kernel syscall functionality itself; when
/// syscalls are issued, the kernel returns error codes as distinct negative values
/// in the range `-4095..=-1`, so errno is purely a libc convention, which we
/// nonetheless implement here.
///
/// The generic parameter is the return type of the wrapped call
/// ([libc::c_long] for [libc::syscall], [libc::ssize_t] for read(2)-style
/// calls).
#[repr(transparent)]
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SyscallResult<V>(pub V);

impl<V> SyscallResult<V> {
    /// Access to [Self::0]
    pub fn raw_value(&self) -> V
    where
        V: Copy,
    {
        self.0
    }
}

impl<V: Signed + Copy> SyscallResult<V> {
    /// Claim the syscall result as a raw value; i.e. this can be used to
    /// turn the syscall result into a [Result] with an [rustix::io::Errno]
    ///
    /// - If [Self::raw_value] is negative, then [try_errno()] is called to retrieve the errno
    /// - Otherwise the value is returned unchanged
    ///
    /// # Panic
    ///
    /// Panics if [Self::raw_value] is negative but errno is 0.
    pub fn claim_value(&self) -> Result<V, rustix::io::Errno> {
        if !self.0.is_negative() {
            return Ok(self.0);
        }

        try_errno()
            .expect("system call returned an error result but no error number is set (errno = 0)")
            .apply(Err)
    }
}

impl SyscallResult<libc::c_long> {
    /// Claim the system call result as a file descriptor
    ///
    /// - Error results are handled as in [Self::claim_value]
    /// - Otherwise, this just forwards to [rustix::fd::OwnedFd::from_raw_fd]
    ///
    /// # Panic
    ///
    /// Panics if the claimed value exceeds [i32::MAX], or as [Self::claim_value].
    ///
    /// # Safety
    ///
    /// Refer to [rustix::fd::OwnedFd::from_raw_fd].
    pub unsafe fn claim_fd(&self) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
        match self.claim_value()? {
            fd if fd > i32::MAX.into() => panic!("File descriptor `{fd}` is out of bounds!"),
            fd => Ok(unsafe { rustix::fd::OwnedFd::from_raw_fd(fd as i32) }),
        }
    }
}

impl SyscallResult<libc::ssize_t> {
    /// Claim the result of a read(2)-style system call as a byte count
    ///
    /// Error results are handled as in [Self::claim_value].
    pub fn claim_byte_count(&self) -> Result<usize, rustix::io::Errno> {
        Ok(self.claim_value()? as usize)
    }
}

impl<V> From<V> for SyscallResult<V> {
    fn from(value: V) -> Self {
        Self(value)
    }
}
