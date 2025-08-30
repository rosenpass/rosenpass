//! Helpers for performing system calls

use std::os::fd::FromRawFd;

use super::errno;

/// Wrapper type around [libc::c_long] that indicates that this value represents
/// the result of a system call
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
    /// - If [Self::raw_value] < 0, then [errno()] is called to retrieve the error type
    /// - If [Self::raw_value] > [i32::MAX], panics
    /// - Otherwise, this just forwards to [rustix::fd::OwnedFd::from_raw_fd]
    ///
    /// # Panic
    ///
    /// Panics if [Self::raw_value] > [i32::MAX].
    ///
    /// # Safety
    ///
    /// Refer to [rustix::fd::OwnedFd::from_raw_fd].
    pub unsafe fn claim_fd(&self) -> Result<rustix::fd::OwnedFd, rustix::io::Errno> {
        let fde = self.0;
        match fde {
            e if e < 0 => Err(errno()),
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
