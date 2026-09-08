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
#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum MemfdSecretError {
    /// memfd_secret(2) not supported on system
    #[error(
        "Could not create secret memory segment using memfd_secret(2): not supported on your system"
    )]
    NotSupported,
    /// Other error
    #[error("Could not create secret memory segment using memfd_secret(2): underlying system error: {:?}", .0)]
    SystemError(Errno),
}

impl From<Errno> for MemfdSecretError {
    fn from(value: Errno) -> Self {
        match value {
            Errno::NOSYS => Self::NotSupported,
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
///     // The system might not have memfd_secret enabled; abort the test
///     Err(E::NotSupported) => return Ok(()),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memfd_secret_cloexec() {
        use Errno as E;
        use MemfdSecretError as M;
        match memfd_secret(MemfdSecretFlags::empty()) {
            Ok(fd) => drop(fd),
            Err(M::NotSupported | M::SystemError(E::INVAL | E::PERM)) => return,
            Err(e) => panic!("Unexpected error probing memfd_secret(2): {e:?}"),
        }

        // (a) Creating a secret memfd with CLOEXEC set must succeed
        let fd = memfd_secret(MemfdSecretFlags::CLOEXEC)
            .expect("memfd_secret(2) with CLOEXEC failed although the probe succeeded");

        // (b) The close-on-exec flag must be set on the new file descriptor
        let fdflags = rustix::io::fcntl_getfd(&fd).expect("fcntl(F_GETFD) failed");
        assert!(fdflags.contains(rustix::io::FdFlags::CLOEXEC));
    }
}
