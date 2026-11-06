//! Utilities for working with memory-based file descriptors

use std::os::fd::{AsFd, OwnedFd};

use rustix::io::Errno;
use rustix::path::Arg as Path;

use bitflags::bitflags;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub use rustix::fs::MemfdFlags;

use crate::internal::util::result::OkExt;

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
bitflags! {
    /// Linux memfd_create(2) flags accepted by the unsupported-platform stub.
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct MemfdFlags: std::ffi::c_uint {
        /// Close the file descriptor on exec.
        const CLOEXEC = 0x0001;
        /// Allow adding file seals.
        const ALLOW_SEALING = 0x0002;
        /// Seal the file descriptor against execution.
        const NOEXEC_SEAL = 0x0008;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
bitflags! {
    // SealFlags on any platform; these are just used so we can express sealing logic
    // at runtime and detect unavailability of seals at runtime, instead of having to use
    // compile-time conditionals
    #[repr(transparent)]
    #[derive(Copy, Clone, Eq, PartialEq, Hash, Debug)]
    pub struct SealFlagsPortable: std::ffi::c_uint {
        const SEAL = 0x0001;
        const SHRINK = 0x0002;
        const GROW = 0x0004;
        const WRITE = 0x0008;
        const FUTURE_WRITE = 0x0010;
        const EXEC = 0x0020;
    }
}

/// File seal flags (`F_SEAL_*`)
pub type SealFlags = cfg_select! {
    any(target_os = "linux", target_os = "freebsd") => rustix::fs::SealFlags,
    _ => SealFlagsPortable,
};

/// Create an anonymous file
/// using the memfd_create(2) syscall
///
/// On Linux and FreeBSD, forwards to [rustix::fs::memfd_create]
///
/// On all other platforms, returns ENOSYS without calling the kernel
pub fn memfd_create<P: Path>(name: P, flags: MemfdFlags) -> rustix::io::Result<OwnedFd> {
    cfg_select! {
        any(target_os = "linux", target_os = "freebsd") => rustix::fs::memfd_create(name, flags),
        _ => {
            let _ = (name, flags);
            Err(Errno::NOSYS)?
        }
    }
}

/// Errors for adding file seals (F_ADD_SEALS) to a file descriptor
///
/// Adding seals is retried a bounded number of times, because adding seals
/// can race with another party sealing the same file descriptor
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AddSealsError {
    /// Adding the seals was retried many times, but never succeeded
    #[error(
        "Tried to add file seals to the file descriptor many times, but we never succeeded. This likely is a bug"
    )]
    TooManyRetries,
    /// One of the fcntl(2) system calls used for sealing failed
    #[error(
        "Tried to add file seals to the file descriptor, but one of the fcntl(2) system calls failed: {0}"
    )]
    SystemError(#[from] rustix::io::Errno),
    /// The file descriptor is already sealed against adding further seals while
    /// still missing seals we need to add
    #[error(
        "Tried to add file seals to the file descriptor, but the file descriptor already carried F_SEAL_SEAL, so the seals could not be added."
    )]
    CannotAddFurtherSeals,
}

/// (F_SEAL_SEAL): Never installed; used only to detect file
/// descriptors that are already sealed against adding further seals
///
/// Not installing it keeps the seal set open for later seals (e.g.
/// F_SEAL_FUTURE_WRITE); third parties can only add seals, never remove ours.
pub const SSEAL: SealFlags = SealFlags::SEAL;

/// Inspect and add the file seals (`F_SEAL_*`) of a file descriptor.
///
/// Seals belong to the file, so duplicated descriptors observe the same
/// seals; they can only be added, never removed. Sealing must be enabled at
/// creation (e.g. `memfd_create` with `MFD_ALLOW_SEALING`).
///
/// Linux and FreeBSD only; on other platforms every operation fails with ENOSYS.
pub trait FileSealsExt {
    /// The file's current seals.
    fn seals(&self) -> rustix::io::Result<SealFlags>;
    /// Add the given seals to the file.
    fn add_seals(&self, seals: SealFlags) -> Result<(), AddSealsError>;
    /// Whether all of the given seals are set on the file.
    fn has_all_of_these_seals(&self, required: SealFlags) -> rustix::io::Result<bool>;
    /// Whether any of the given seals are set on the file.
    fn has_any_of_these_seals(&self, mask: SealFlags) -> rustix::io::Result<bool>;
}

impl<T> FileSealsExt for T
where
    T: AsFd,
{
    fn seals(&self) -> rustix::io::Result<SealFlags> {
        cfg_select! {
            any(target_os = "linux", target_os = "freebsd") => rustix::fs::fcntl_get_seals(self),
            _ => Err(Errno::NOSYS),
        }
    }

    fn add_seals(&self, seals: SealFlags) -> Result<(), AddSealsError> {
        cfg_select! {
            any(target_os = "linux", target_os = "freebsd") => add_seals_impl(self, seals),
            _ => {
                let _ = seals;
                Err(AddSealsError::SystemError(Errno::NOSYS))
            }
        }
    }

    fn has_all_of_these_seals(&self, required: SealFlags) -> rustix::io::Result<bool> {
        self.seals()?.contains(required).ok()
    }

    fn has_any_of_these_seals(&self, mask: SealFlags) -> rustix::io::Result<bool> {
        self.seals()?.intersects(mask).ok()
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn add_seals_impl<Fd>(fd: Fd, seals: SealFlags) -> Result<(), AddSealsError>
where
    Fd: FileSealsExt + AsFd,
{
    use AddSealsError as E;

    let mut seal_ctr: usize = usize::MAX;
    let mut prev_seals: Option<SealFlags> = None;
    loop {
        // Increment the loop counter
        seal_ctr = seal_ctr.overflowing_add(1).0;

        // Abort this loop after too many failed attempts just to be safe
        if seal_ctr >= 16 {
            Err(E::TooManyRetries)?;
        }

        // Add the seals
        //
        // The call succeeding and failing with permission denied are both
        // handled the same way: fetch the list of seals below and check
        // what seals we actually got
        //
        // Permission denied could happen because F_SEAL_SEAL raced in
        // concurrently (detected via the seal set below and reported as
        // CannotAddFurtherSeals), or because the file descriptor is
        // not writable — adding seals requires a writable file descriptor;
        // that case can never make progress and is detected by the
        // no-progress check below
        let add_denied = match rustix::fs::fcntl_add_seals(&fd, seals) {
            Ok(()) => false,
            Err(Errno::PERM) => true,
            // Other error; just propagate this error to the function caller
            Err(errno) => return Err(E::SystemError(errno))?,
        };

        // Figure out what seals are set and which ones we need to add
        let current_seals = fd.seals().map_err(E::SystemError)?;
        let missing = seals.difference(current_seals);

        // Unable to add the missing seals, FD is already sealed against adding further seals
        if current_seals.contains(SSEAL) && !missing.is_empty() {
            Err(E::CannotAddFurtherSeals)?;
        }

        // Adding seals was denied and the seal set did not change since the
        // last attempt: no progress is possible (e.g. the file descriptor
        // is not writable), so retrying would merely spin until the retry
        // limit; report the persistent permission error instead
        if add_denied && prev_seals == Some(current_seals) {
            Err(E::SystemError(Errno::PERM))?;
        }
        prev_seals = Some(current_seals);

        // Missing seals, but not sealed against further seals. Try to add the seals we need.
        if !missing.is_empty() {
            continue;
        }

        // Sealing successful; now aborting
        return Ok(());
    }
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
        "memfd_secret(2) is not supported on your system or, on Linux, was blocked at boot by using the kernel command line `secretmem.enable=0`"
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
    cfg_select! {
        target_os = "linux" => {
            use crate::internal::util::convert::IntoTypeExt;
            use super::SyscallResult;

            let res = unsafe {
                use libc::{SYS_memfd_secret, syscall};
                syscall(SYS_memfd_secret, flags)
                    .into_type::<SyscallResult<_>>()
                    .claim_fd()
            };

            res.map_err(MemfdSecretError::from)
        },
        _ => {
            let _ = flags;
            Err(Errno::NOSYS)?
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal::util::rustix::DescriptorFlagsExt;

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
        let fdflags = fd.fd_flags().expect("fcntl(F_GETFD) failed");
        assert!(!fdflags.contains(rustix::io::FdFlags::CLOEXEC));

        // Creating a secret memfd with CLOEXEC set must also succeed
        let fd = memfd_secret(MemfdSecretFlags::CLOEXEC)
            .expect("memfd_secret(2) with CLOEXEC failed although the probe succeeded");

        // Now, the close-on-exec flag must be set on the new file descriptor
        let fdflags = fd.fd_flags().expect("fcntl(F_GETFD) failed");
        assert!(fdflags.contains(rustix::io::FdFlags::CLOEXEC));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_seal_flags_ext() -> anyhow::Result<()> {
        use rustix::fs::SealFlags;

        let fd = memfd_create(c"seal-ext-test", MemfdFlags::ALLOW_SEALING)?;

        // A fresh memfd created with ALLOW_SEALING does not carry any seals yet
        assert!(fd.seals()?.is_empty());

        // Seals accumulate and can never be removed again
        fd.add_seals(SealFlags::GROW | SealFlags::SHRINK)?;
        assert!(fd.has_all_of_these_seals(SealFlags::GROW | SealFlags::SHRINK)?);
        assert!(!fd.has_any_of_these_seals(SealFlags::WRITE)?);

        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn test_seal_flags_ext_unsealable_socket() {
        let (socket, _peer) = std::os::unix::net::UnixStream::pair().unwrap();

        // Sockets do not support sealing
        let err = socket
            .seals()
            .expect_err("seal_flags() on a socket must fail");
        assert_eq!(err, Errno::INVAL);
    }
}
