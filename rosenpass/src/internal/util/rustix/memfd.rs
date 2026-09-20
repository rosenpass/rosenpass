//! Utilities for working with memory-based file descriptors

use std::os::fd::OwnedFd;

use rustix::fs::MemfdFlags;
use rustix::io::Errno;
use rustix::path::Arg as Path;

use bitflags::bitflags;

use crate::internal::util::convert::IntoTypeExt;

use super::SyscallResult;

/// Create an anonymous file
/// using the memfd_create(2) syscall
///
/// Just forwards to [rustix::fs::memfd_create]
pub fn memfd_create<P: Path>(name: P, flags: MemfdFlags) -> rustix::io::Result<OwnedFd> {
    rustix::fs::memfd_create(name, flags)
}

bitflags! {
    /// `O_*` constants for use with [memfd_secret].
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct MemfdSecretFlags: std::ffi::c_uint {
        /// O_CLOEXEC
        const CLOEXEC = libc::O_CLOEXEC as std::ffi::c_uint;
    }
}

/// Errors for [memfd_secret()]
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum MemfdSecretUnavailabilityReason {
    /// memfd_secret(2) is not supported by the kernel or was disabled at boot
    #[error(
        "memfd_secret(2) is not supported on your system or was blocked at boot by using the kernel command line `secretmem.enable=0`"
    )]
    NotSupported,
    /// memfd_secret(2) is blocked by a security policy (seccomp/LSM) on this system
    #[error("memfd_secret(2) is blocked by a security policy (seccomp/LSM) on your system")]
    BlockedByPolicy,
}

/// Errors for [memfd_secret()]
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum MemfdSecretError {
    /// memfd_secret(2) is unavailable on this system
    #[error("Could not create secret memory segment using memfd_secret(2): {}", .0)]
    Unavailable(#[from] MemfdSecretUnavailabilityReason),
    /// memfd_secret(2) failed with an unexpected system error
    #[error("Could not create secret memory segment using memfd_secret(2): underlying system error: {}", .0)]
    SystemError(Errno),
}

impl From<Errno> for MemfdSecretError {
    fn from(value: Errno) -> Self {
        use MemfdSecretUnavailabilityReason as Unavail;
        match value {
            Errno::NOSYS => Unavail::NotSupported.into(),
            Errno::PERM | Errno::ACCESS => Unavail::BlockedByPolicy.into(),
            e => Self::SystemError(e),
        }
    }
}

/// Create an anonymous RAM-based file to access secret memory regions
/// using the memfd_secret(2) syscall
///
/// # Examples
///
#[cfg_attr(feature = "expose_internal_modules", doc = "```")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
/// use rustix::io::Errno;
/// use rustix::fs::ftruncate;
///
/// use rosenpass::internal::util::rustix::{memfd_secret, MemfdSecretFlags, IntoStdioErr, MemfdSecretError};
/// use rosenpass::internal::util::io::handle_interrupted;
///
/// let res = memfd_secret(MemfdSecretFlags::empty());
///
/// use MemfdSecretError as E;
/// let fd = match res {
///     Ok(fd) => fd,
///     Err(E::Unavailable(_)) => return Ok(()), // Blocked, disabled, or not supported
///     Err(E::SystemError(err)) => return Err(err)?,
/// };
///
/// handle_interrupted(|| { ftruncate(&fd, 8192).into_stdio_err() })?;
///
/// Ok::<(), anyhow::Error>(())
/// ```
pub fn memfd_secret(flags: MemfdSecretFlags) -> Result<rustix::fd::OwnedFd, MemfdSecretError> {
    let res = unsafe {
        use libc::{SYS_memfd_secret, syscall};
        syscall(SYS_memfd_secret, flags)
            .into_type::<SyscallResult>()
            .claim_fd()
    };

    res.map_err(MemfdSecretError::from)
}

/// Extension trait for [rustix::fs::StatFs] to determine whether
/// a file descriptor is a memfd_secret(2)
#[cfg(target_os = "linux")]
pub trait IsMemfdSecretExt {
    /// Determine whether the underlying file descriptor that generated this [rustix::fs::StatFs]
    /// is a memfd_secret(2) file descriptor
    fn is_memfd_secret(&self) -> bool;
}

#[cfg(target_os = "linux")]
impl IsMemfdSecretExt for rustix::fs::StatFs {
    fn is_memfd_secret(&self) -> bool {
        const SECRETMEM_MAGIC: rustix::fs::FsWord = 0x5345_434d;
        self.f_type == SECRETMEM_MAGIC
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memfd_secret_cloexec() {
        // Creating a memfd_secret without any flags must succeed (unless the
        // feature is unavailable, in which case we skip the test)
        let fd = match memfd_secret(MemfdSecretFlags::empty()) {
            Ok(fd) => fd,
            Err(MemfdSecretError::Unavailable(_)) => return,
            Err(e) => panic!("Unexpected error probing memfd_secret(2): {e:?}"),
        };

        // This yields a file descriptor without the close on exec flag set
        let fdflags = rustix::io::fcntl_getfd(&fd).expect("fcntl(F_GETFD) failed");
        assert!(!fdflags.contains(rustix::io::FdFlags::CLOEXEC));

        // Creating a secret memfd with CLOEXEC set must also succeed
        let fd = memfd_secret(MemfdSecretFlags::CLOEXEC)
            .expect("memfd_secret(2) with CLOEXEC failed although the probe succeeded");

        // Now, the close-on-exec flag must be set on the new file descriptor
        let fdflags = rustix::io::fcntl_getfd(&fd).expect("fcntl(F_GETFD) failed");
        assert!(fdflags.contains(rustix::io::FdFlags::CLOEXEC));
    }
}
