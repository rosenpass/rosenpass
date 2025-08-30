//! Creation of secret memory file descriptors.
//!
//! This essentially provides a higher_level API for [memfd_secret()] and [memfd_create()]

// Tests: This uses nix-based integration tests

use std::{os::fd::OwnedFd, sync::OnceLock};

use rustix::{fs::MemfdFlags, io::Errno};

use crate::rustix::{memfd_create, memfd_secret, MemfdSecretError, MemfdSecretFlags};
use crate::{mem::CopyExt, result::OkExt};

/// Cache for [memfd_secret_supported]
static MEMFD_SECRET_SUPPORTED: OnceLock<bool> = OnceLock::new();

/// Check whether support for memfd_secret is available
pub fn memfd_secret_supported() -> Result<bool, Errno> {
    match MEMFD_SECRET_SUPPORTED.get() {
        Some(v) => return Ok(*v),
        _ => {} // Continue
    };

    use MemfdSecretError as E;
    let is_supported = match memfd_secret(MemfdSecretFlags::empty()) {
        Ok(_) => true,
        Err(E::NotSupported) => false,
        Err(E::SystemError(e)) => return Err(e),
    };

    // We are deliberately using get_or_init here to make sure that the entire application
    // never sees different values here
    MEMFD_SECRET_SUPPORTED
        .get_or_init(|| is_supported)
        .copy()
        .ok()
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

/// Which mechanism to us use when allocating secret memory file descriptors
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

        match memfd_secret_supported()? {
            true => Ok(M::MemfdSecret),
            false => Ok(M::MemfdCreate),
        }
    }
}

/// Errors for [create_memfd_secret()]
#[derive(Copy, Clone, Debug, thiserror::Error)]
pub enum SecretMemfdWithConfigError {
    /// Call to [memfd_secret()] failed
    #[error("{:?}", .0)]
    MemfdSecretError(#[from] MemfdSecretError),
    /// Call to [memfd()] failed
    #[error("Could not create secret memory segment using memfd_create(2) due to underlying system error: {:?}", .0)]
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
#[derive(Default, Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq)]
pub struct SecretMemfdConfig {
    /// Enable  the  close-on-exec flag for the new file descriptor.
    pub close_on_exec: bool,
    /// Security mechanism to use
    pub policy: SecretMemfdPolicy,
}

impl SecretMemfdConfig {
    /// Create a new, default [Self]
    pub const fn new() -> Self {
        let close_on_exec = false;
        let policy = SecretMemfdPolicy::default_const();
        Self {
            close_on_exec,
            policy,
        }
    }

    /// Set the [Self::close_on_exec] flag to true
    pub const fn cloexec(&self) -> Self {
        let mut r = *self;
        r.close_on_exec = true;
        r
    }

    /// Set `self.policy = SecretMemoryFdPolicy::UseMemfdSecret`
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
    pub fn create(&self) -> Result<OwnedFd, SecretMemfdWithConfigError> {
        use SecretMemfdWithConfigError as E;
        let mech = self.mechanism().map_err(E::FailedToDetectSupport)?;

        use SecretMemfdMechanism as M;
        match (mech, self.close_on_exec) {
            (M::MemfdCreate, cloexec) => {
                let flags = match cloexec {
                    true => MemfdFlags::CLOEXEC,
                    false => MemfdFlags::empty(),
                };
                memfd_create("rosenpass secret memory segment", flags).map_err(E::MemfdCreateError)
            }
            (M::MemfdSecret, cloexec) => {
                let flags = match cloexec {
                    true => MemfdSecretFlags::CLOEXEC,
                    false => MemfdSecretFlags::empty(),
                };
                memfd_secret(flags).map_err(E::MemfdSecretError)
            }
        }
    }
}

/// Create a secret memory file descriptor using the default policy
///
/// Shorthand for
/// [`SecretMemfdConfig`][`::new()`](SecretMemfdConfig::new)[`.create()`](SecretMemfdConfig::create)
pub fn memfd_for_secrets_with_default_policy() -> Result<OwnedFd, SecretMemfdWithConfigError> {
    SecretMemfdConfig::new().create()
}
