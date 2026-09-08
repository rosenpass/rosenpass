//! Creation of secret memory file descriptors.
//!
//! This essentially provides a higher-level API for [memfd_secret()] and [memfd_create()]

use std::{os::fd::OwnedFd, sync::OnceLock};

use rustix::{fs::MemfdFlags, io::Errno};

use crate::internal::util::mem::CopyExt;
use crate::internal::util::rustix::{
    MemfdSecretError, MemfdSecretFlags, MemfdSecretUnavailabilityReason, memfd_create, memfd_secret,
};

/// Cache for [memfd_secret_supported]
static MEMFD_SECRET_SUPPORTED: OnceLock<Result<(), MemfdSecretUnavailabilityReason>> =
    OnceLock::new();

/// Check whether support for memfd_secret is available
///
/// This really just calls [memfd_secret()] to test if it works.
///
/// If the call succeeds, then this result will be cached and returned
/// as `Ok(Ok(()))`
///
/// If the call fails because memfd_secret(2) is unavailable
/// ([`MemfdSecretError::Unavailable(reason)`](MemfdSecretError::Unavailable)),
/// then this result will be cached and the error will be returned in the inner result,
/// i.e. as `Ok(Err(reason))`.
///
/// If the call fails for some other reason ([`MemfdSecretError::SystemError(errno)`](MemfdSecretError::SystemError)),
/// then this result is not cached and the system error (i.e. the errno) is returned
/// in the outer result, i.e. as `Err(errno)`.
pub fn memfd_secret_supported() -> Result<Result<(), MemfdSecretUnavailabilityReason>, Errno> {
    match MEMFD_SECRET_SUPPORTED.get() {
        Some(v) => return Ok(*v),
        _ => {} // Continue
    };

    use MemfdSecretError as E;
    let v = match memfd_secret(MemfdSecretFlags::CLOEXEC) {
        // Succeeded; immediately drop/close the file descroptor
        Ok(_) => Ok(()),
        // Persistent failure; we must cache this
        Err(E::Unavailable(e)) => Err(e),
        // Other/unknown system error; we must not cache this. Return immediately.
        Err(E::SystemError(e)) => return Err(e),
    };

    // We are deliberately using get_or_init here to make sure that the entire application
    // never sees different values here
    let v = MEMFD_SECRET_SUPPORTED.get_or_init(|| v).copy();

    Ok(v)
}

/// How secure memory file descriptors should be allocated
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub enum SecretMemfdPolicy {
    /// Use memfd_secret(2) if available, otherwise fall back to less
    /// secure options
    Opportunistic,
    /// Enforce the use of memfd_secret(2)
    UseMemfdSecret,
    /// Never use memfd_secret(2)
    DisableMemfdSecret,
}

impl Default for SecretMemfdPolicy {
    fn default() -> Self {
        Self::Opportunistic
    }
}

impl SecretMemfdPolicy {
    /// Create a SecretMemfdPolicy with the default policy
    ///
    /// Currently [Self::Opportunistic]
    pub const fn default_const() -> Self {
        Self::Opportunistic
    }

    /// Enforce the use of the highest security configuration available
    ///
    /// This might not work on some systems, which is why this is not used
    /// by default.
    ///
    /// Currently [Self::UseMemfdSecret]
    pub const fn enforce_high_security() -> Self {
        Self::UseMemfdSecret
    }
}

/// Which mechanism to use when allocating secret memory file descriptors
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub enum SecretMemfdMechanism {
    /// The less secure memfd_create(2) will be used
    MemfdCreate,
    /// The more secure memfd_secret(2) will be used
    MemfdSecret,
}

impl SecretMemfdMechanism {
    /// Decide which mechanism to use, based on the given [SecretMemfdPolicy]
    /// and [memfd_secret_supported()].
    ///
    /// If [SecretMemfdPolicy::UseMemfdSecret] is used, then [SecretMemfdMechanism::MemfdSecret]
    /// will be returned, regardless of whether it is supported.
    ///
    /// Likewise, if [SecretMemfdPolicy::DisableMemfdSecret] is used, then
    /// [SecretMemfdMechanism::MemfdCreate] will be used unconditionally.
    pub fn decide_with_policy(policy: SecretMemfdPolicy) -> Result<Self, Errno> {
        use SecretMemfdMechanism as M;
        use SecretMemfdPolicy as P;

        match policy {
            P::UseMemfdSecret => return Ok(M::MemfdSecret),
            P::DisableMemfdSecret => return Ok(M::MemfdCreate),
            P::Opportunistic => {}
        };

        match memfd_secret_supported()?.is_ok() {
            true => Ok(M::MemfdSecret),
            false => Ok(M::MemfdCreate),
        }
    }
}

/// Errors for [SecretMemfdConfig::create()]
#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum SecretMemfdWithConfigError {
    /// Call to [memfd_secret()] failed
    #[error("{:?}", .0)]
    MemfdSecretError(#[from] MemfdSecretError),
    /// Call to [memfd_create()] failed
    #[error("Could not create secret memory segment using memfd_create(2) due to an underlying system error: {:?}", .0)]
    MemfdCreateError(Errno),
    /// Some other (system) error occurred that prevented us from determining whether
    /// memfd_secret(2) is supported.
    #[error("Failed to determine whether memfd_secret(2) is supported due to underlying system error: {:?}", .0)]
    FailedToDetectSupport(Errno),
}

/// Robustly configure and create secret memory file descriptors
///
/// Whereas [memfd_secret] will always use memfd_secret(2), this construction allows multiple
/// file descriptor back ends to be used to support different usage scenarios.
///
/// This is necessary, because older systems do not support memfd_secret(2) and using it might not
/// always be desirable, as memfd_secret for instance also inhibits hibernation.
///
/// The close-on-exec file descriptor flag (FD_CLOEXEC) is always set on
/// the file descriptors produced by [Self::create()].
///
/// The default configuration ([Self::new()], [Self::default()]) uses the
/// default ([SecretMemfdPolicy::Opportunistic]) policy.
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub struct SecretMemfdConfig {
    /// Security mechanism to use
    pub policy: SecretMemfdPolicy,
}

impl Default for SecretMemfdConfig {
    fn default() -> Self {
        Self::new()
    }
}

impl SecretMemfdConfig {
    /// Create a new, default [Self]
    ///
    /// Uses the default ([SecretMemfdPolicy::Opportunistic]) policy. The
    /// close-on-exec file descriptor flag is always set on the produced
    /// file descriptor; see the struct-level documentation.
    pub const fn new() -> Self {
        let policy = SecretMemfdPolicy::default_const();
        Self { policy }
    }

    /// Set `self.policy = SecretMemfdPolicy::UseMemfdSecret`
    pub const fn enforce_high_security(&self) -> Self {
        let mut r = *self;
        r.policy = SecretMemfdPolicy::enforce_high_security();
        r
    }

    /// Whether memfd_secret will be used by [Self::create()]
    pub fn mechanism(&self) -> Result<SecretMemfdMechanism, Errno> {
        SecretMemfdMechanism::decide_with_policy(self.policy)
    }

    /// Allocate a secret file descriptor based on the configuration
    ///
    /// The close-on-exec file descriptor flag is always set on the
    /// produced file descriptor.
    ///
    /// On the memfd_create(2) backend, the file descriptor is additionally
    /// sealed non-executable (MFD_NOEXEC_SEAL) where the kernel supports it
    /// (Linux >= 6.3).
    pub fn create(&self) -> Result<OwnedFd, SecretMemfdWithConfigError> {
        use SecretMemfdWithConfigError as E;
        let mech = self.mechanism().map_err(E::FailedToDetectSupport)?;

        use SecretMemfdMechanism as M;
        match mech {
            // We have to use MemfdCreate; this is the harder case handled below
            M::MemfdCreate => (),
            // The kernel accepts no memfd_secret(2) flag other than O_CLOEXEC
            // Since this is the easy case, we handle it here
            M::MemfdSecret => {
                return memfd_secret(MemfdSecretFlags::CLOEXEC).map_err(E::MemfdSecretError);
            }
        };

        use MemfdFlags as F;
        let name = "rosenpass secret memory segment";

        // memfd_secret(2) appears to be unsupported; fall back to memfd_create(2)
        match memfd_create(name, F::CLOEXEC | F::NOEXEC_SEAL) {
            // Invalid call; probably means that NOEXEC_SEAL is not supported on this kernel
            Err(Errno::INVAL) => (),
            // Valid result, immediately return
            res => return res.map_err(E::MemfdCreateError),
        }

        // NOEXEC_SEAL appears to be unsupported for memfd_create(2); fall back to not using it
        memfd_create("rosenpass secret memory segment", MemfdFlags::CLOEXEC)
            .map_err(E::MemfdCreateError)
    }
}

/// Create a secret memory file descriptor using the default policy
///
/// Shorthand for
/// [`SecretMemfdConfig::new()`] followed by [`SecretMemfdConfig::create()`]
pub fn memfd_for_secrets_with_default_policy() -> Result<OwnedFd, SecretMemfdWithConfigError> {
    SecretMemfdConfig::new().create()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_created_secret_memfds_are_close_on_exec() {
        fn assert_close_on_exec(fd: &OwnedFd) {
            let fd_flags = rustix::io::fcntl_getfd(fd).expect("fcntl(F_GETFD) failed");
            assert!(fd_flags.contains(rustix::io::FdFlags::CLOEXEC));
        }

        // memfd_create(2) backend
        let cfg = SecretMemfdConfig {
            policy: SecretMemfdPolicy::DisableMemfdSecret,
        };
        assert_close_on_exec(&cfg.create().expect("memfd_create(2) failed"));

        // memfd_secret(2) backend, on systems that support it
        if memfd_secret_supported()
            .expect("probing memfd_secret(2) support failed")
            .is_ok()
        {
            let cfg = SecretMemfdConfig {
                policy: SecretMemfdPolicy::UseMemfdSecret,
            };
            assert_close_on_exec(
                &cfg.create()
                    .expect("memfd_secret(2) failed although support was reported"),
            );
        }

        // The default policy, on whichever backend it selects
        assert_close_on_exec(
            &SecretMemfdConfig::new()
                .create()
                .expect("creating a secret memfd with the default policy failed"),
        );
    }
}
