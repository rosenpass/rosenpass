//! Creation of secret memory file descriptors.
//!
//! This essentially provides a higher-level API for [memfd_secret()] and [memfd_create()]

use std::{os::fd::OwnedFd, sync::OnceLock};

use rustix::fs::ftruncate;
use rustix::{fs::MemfdFlags, io::Errno};

use crate::internal::util::result::OkExt;
use crate::internal::util::rustix::{
    MemfdSecretError, MemfdSecretFlags, MemfdSecretUnavailabilityReason, memfd_create, memfd_secret,
};
use crate::internal::util::secret_memory::mmap::{MapFdConfig, MappableFd};

/// Type indicating the level of support for memfd_secret(2), returned by
/// [memfd_secret_support()]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct MemfdSecretSupport {
    /// Whether memfd_secret protects against resizing (see [memfd_secret_support()])
    pub protected_against_resizing: bool,
}

/// Cache for [memfd_secret_support]
static MEMFD_SECRET_SUPPORT: OnceLock<Result<MemfdSecretSupport, MemfdSecretUnavailabilityReason>> =
    OnceLock::new();

/// Detects the level of support for memfd_secret(2) in the system.
///
/// There are three tiers:
///
/// 1. memfd_secret(2) supported unconditionally
/// 2. memfd_secret(2) supported, but not for shared memory applications
///     - Missing support for auto-sealing memfd_secret(2) file descriptors against
///       truncation/resizing
/// 3. No memfd_secret(2) support at all, because of one of these reasons:
///     - Operating system does not support memfd_secret(2) (other than Linux)
///     - Kernel does not support memfd_secret(2) (Linux, but too old)
///     - memfd_secret(2) was disabled at boot through the kernel command line
///     - memfd_secret(2) is disabled by policy (e.g. seccomp)
///
/// This function returns a fairly complex type:
///
/// - `Ok(Ok(MemfdSecretSupport { protected_against_resizing: true }))` – Full support
/// - `Ok(Ok(MemfdSecretSupport { protected_against_resizing: false }))` – No shared-memory support
/// - `Ok(Err(reason))` – No support on this system; you can inspect the reason for further details
///   about why support is unavailable
/// - `Err(errno)` – Unexpected error during the detection process; it is unclear whether
///   memfd_secret(2) is supported
///
/// The detection function generally runs once and the result is cached by the application.
/// This means that calls to [memfd_secret_support] should be considered cheap.
/// Only the `Err(errno)` result is not cached; this is a deliberate choice since this is the
/// "other unknown error" return code.
///
/// The detection works like this:
///
/// 1. Call memfd_secret(2) and get a memfd_secret file descriptor
///     - If this returns an error indicating that support is completely unavailable, we cache and
///       return this information as `Ok(Err(reason))`
///     - If this returns another error, we report this as `Err(errno)`
/// 2. Call ftruncate(2) to resize the file descriptor
///     - If this returns any error, we report this as `Err(errno)`
/// 3. Call ftruncate(2) again
///     - If this call succeeds, then auto-sealing is disabled and shared memory usage is not supported.
///       Reported as `Ok(Ok(MemfdSecretSupport { protected_against_resizing: false }))`.
///     - If this call fails with EINVAL, then auto-sealing is active and shared memory usage is
///       supported. Reported as `Ok(Ok(MemfdSecretSupport { protected_against_resizing: true }))`.
///
/// ## Auto-sealing
///
/// On newer Linux kernels, memfd_secret(2) admits exactly one call to ftruncate(2). I.e. you are
/// allowed to set the size of the file descriptor once, but any attempts to resize the file are
/// denied.
///
/// On older Linux kernels, memfd_secret(2) did not have this protection against resizing the file
/// descriptors. It is these systems on which we enable memfd_secret(2) for local use, but not for
/// shared memory use as a defense against the following attack.
///
/// 1. Two processes, Alice (honest) and Eve (attacker) hold the same file descriptor FD
/// 2. Alice maps FD into memory, detecting the size of FD using fstat(2) or by coordinating with
///    Eve in some other way
/// 3. Eve truncates FD after Alice has mapped FD into their address space, remotely invalidating
///    the memory pages held by Alice
/// 4. Alice tries to access the address space that FD was mapped into triggering SIGBUS (or
///    SIGSEGV); their process crashes
///
/// This ability to remotely invalidate memory pages held by Alice is the reason we require the
/// protection against truncation.
///
/// When memfd_create(2) is used instead of memfd_secret(2), then [SecretMemfdConfig::create()]
/// will specify the ALLOW_SEALING flag during file descriptor creation. This is later used by
/// [super::mmap::MappableFd::mmap()] to manually seal the file descriptor against resizing using
/// appropriate fcntl(2) calls, defending against the same attack
pub fn memfd_secret_support()
-> Result<Result<MemfdSecretSupport, MemfdSecretUnavailabilityReason>, Errno> {
    if let Some(v) = MEMFD_SECRET_SUPPORT.get() {
        return Ok(*v);
    };

    let v = 'test: {
        use MemfdSecretError as E;
        let fd = match memfd_secret(MemfdSecretFlags::CLOEXEC) {
            // Success; let's detect whether shared mappings are supported
            Ok(fd) => fd,
            // Persistent failure; memfd_secret(2) not supported at all; we must cache this
            Err(E::Unavailable(reason)) => break 'test Err(reason),
            // Other/unknown system error; we must not cache this. Return immediately.
            Err(E::SystemError(errno)) => return Err(errno),
        };

        // First truncation should succeed
        ftruncate(&fd, 10)?;

        // Second truncation should be blocked
        use MemfdSecretSupport as S;
        match ftruncate(&fd, 9) {
            // Second truncation was not blocked; this may be an old Linux kernel. Disable
            // memfd_secret usage for shared memory on these systems
            Ok(_) => Ok(S {
                protected_against_resizing: false,
            }),
            // Second truncation was blocked; good, this is the behavior we need
            Err(Errno::INVAL) => Ok(S {
                protected_against_resizing: true,
            }),
            // Other error; do not cache; return as is
            Err(errno) => return Err(errno),
        }
    };

    // We are deliberately using get_or_init here to make sure that the entire application
    // never sees different values here
    let v = MEMFD_SECRET_SUPPORT.get_or_init(|| v);

    Ok(*v)
}

/// Whether memfd_secret(2) is supported for local applications
///
/// Just a wrapper around [memfd_secret_support()] that checks whether the support level
/// matches `Ok(MemfdSecretSupport { .. })`.
pub fn memfd_secret_supported_for_local_applications() -> Result<bool, Errno> {
    let v = memfd_secret_support()?;
    matches!(v, Ok(MemfdSecretSupport { .. })).ok()
}

/// Whether memfd_secret(2) protects against resizing of the file descriptor (see comment in
/// [memfd_secret_support()]).
///
/// Just a wrapper around [memfd_secret_support()] that checks whether the support level
/// matches `Ok(MemfdSecretSupport { protected_against_resizing: true })`.
pub fn memfd_secret_protects_against_resizing() -> Result<bool, Errno> {
    let v = memfd_secret_support()?;
    matches!(
        v,
        Ok(MemfdSecretSupport {
            protected_against_resizing: true
        })
    )
    .ok()
}

/// Whether memfd_secret(2) is supported for shared memory applications
///
/// Just an alias for [memfd_secret_protects_against_resizing()]
pub fn memfd_secret_supported_for_shm_applications() -> Result<bool, Errno> {
    memfd_secret_protects_against_resizing()
}

/// Indicates how the file descriptor generated here will be used
///
/// This is important in some cases; [SecretMemfdMechanism::decide_with_policy]
/// for instance uses this information to disable memfd_secret(2) usage on some hosts
/// where memfd_secret(2) file descriptors are not protected against resizing.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct SecretMemfdUsage {
    /// Whether this file descriptor will be used for shared memory
    pub shared_memory: bool,
}

impl SecretMemfdUsage {
    /// New [SecretMemfdUsage] with the default settings (no particular usage indicated)
    pub const fn default_const() -> Self {
        let shared_memory = false;
        Self { shared_memory }
    }
}

/// How secure memory file descriptors should be allocated
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Ord, Eq, Default)]
pub enum SecretMemfdPolicy {
    /// Use memfd_secret(2) if available, otherwise fall back to less
    /// secure options
    #[default]
    Opportunistic,
    /// Enforce the use of memfd_secret(2)
    UseMemfdSecret,
    /// Never use memfd_secret(2)
    DisableMemfdSecret,
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
    /// Decide which mechanism to use, based on the given [SecretMemfdUsage],
    /// the given [SecretMemfdPolicy], and [memfd_secret_support()].
    ///
    /// The `usage` selects which support level is consulted: shared-memory usage
    /// additionally requires memfd_secret(2) resizing protection.
    ///
    /// If [SecretMemfdPolicy::UseMemfdSecret] is used, then [SecretMemfdMechanism::MemfdSecret]
    /// will be returned, regardless of whether it is supported.
    ///
    /// Likewise, if [SecretMemfdPolicy::DisableMemfdSecret] is used, then
    /// [SecretMemfdMechanism::MemfdCreate] will be used unconditionally.
    pub fn decide_with_policy(
        usage: SecretMemfdUsage,
        policy: SecretMemfdPolicy,
    ) -> Result<Self, Errno> {
        use SecretMemfdMechanism as M;
        use SecretMemfdPolicy as P;

        match policy {
            P::UseMemfdSecret => return Ok(M::MemfdSecret),
            P::DisableMemfdSecret => return Ok(M::MemfdCreate),
            P::Opportunistic => {}
        };

        let memfd_secret_supported_for_usage = match usage.shared_memory {
            false => memfd_secret_supported_for_local_applications()?,
            true => memfd_secret_supported_for_shm_applications()?,
        };

        match memfd_secret_supported_for_usage {
            true => Ok(M::MemfdSecret),
            false => Ok(M::MemfdCreate),
        }
    }
}

/// Errors for [SecretMemfdConfig::validate_config()]
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SecretMemfdConfigValidationError {
    /// [memfd_secret_protects_against_resizing()] is false and the attack described in
    /// [memfd_secret_support()] would be possible with the given configuration since
    /// memfd_secret(2) is used for shared memory
    #[error(
        "\
        The developer has demanded that memfd_secret(2) be used and has indicated that the file descriptor \
        will be used for shared memory between processes. This is fine on most systems, but on this particular \
        system, memfd_secret(2) is not protected against resizing. For this reason, the other process holding \
        the memfd_secret(2) file descriptor could call ftruncate(2) to resize the file, invalidating any memory \
        mappings the local process holds on the file descriptor. The local process can not reliably detect this, \
        instead, upon accessing the now invalid memory, the local process would receive the system signal SIGBUS \
        or SIGSEGV, crashing the process. Since there is no way to defend against this attack on this system when \
        using memfd_secret(2), but the developer demanded that memfd_secret(2) be used for its high level of security, \
        there is no secure way of fulfilling the file descriptor creation request, so we are refusing to fulfill it. \
        This is probably a portability bug."
    )]
    MemfdSecretDoesNotProtectAgainstResizing,
    /// Some other (system) error occurred that prevented us from determining whether
    /// memfd_secret(2) is supported.
    #[error("Failed to determine whether memfd_secret(2) is supported due to an underlying system error: {}", .0)]
    FailedToDetectSupport(Errno),
}

/// Errors for [SecretMemfdConfig::create()]
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum SecretMemfdWithConfigError {
    /// Error reported by [SecretMemfdConfig::validate_config()]
    #[error(transparent)]
    InvalidConfig(#[from] SecretMemfdConfigValidationError),
    /// Call to [memfd_secret()] failed
    #[error(transparent)]
    MemfdSecretError(#[from] MemfdSecretError),
    /// Call to [memfd_create()] failed
    #[error("Could not create secret memory segment using memfd_create(2) due to an underlying system error: {}", .0)]
    MemfdCreateError(Errno),
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
    /// How this file descriptor will be used
    pub usage: SecretMemfdUsage,
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
        let usage = SecretMemfdUsage::default_const();
        let policy = SecretMemfdPolicy::default_const();
        Self { usage, policy }
    }

    /// Indicates that the created file descriptor will be used in shared memory applications
    pub const fn used_in_shared_memory(&self) -> Self {
        let mut r = *self;
        r.usage.shared_memory = true;
        r
    }

    /// Set `self.policy = SecretMemfdPolicy::UseMemfdSecret`
    pub const fn enforce_high_security(&self) -> Self {
        let mut r = *self;
        r.policy = SecretMemfdPolicy::enforce_high_security();
        r
    }

    /// Whether memfd_secret will be used by [Self::create()]
    pub fn mechanism(&self) -> Result<SecretMemfdMechanism, Errno> {
        SecretMemfdMechanism::decide_with_policy(self.usage, self.policy)
    }

    /// Ensure that this configuration is valid and usable
    pub fn validate_config(&self) -> Result<(), SecretMemfdConfigValidationError> {
        use SecretMemfdConfigValidationError as E;
        let mech = self.mechanism().map_err(E::FailedToDetectSupport)?;

        let mfds_use = matches!(mech, SecretMemfdMechanism::MemfdSecret);
        let mfds_prot_resize =
            memfd_secret_protects_against_resizing().map_err(E::FailedToDetectSupport)?;
        let shm_usage = self.usage.shared_memory;

        if mfds_use && shm_usage && !mfds_prot_resize {
            return Err(E::MemfdSecretDoesNotProtectAgainstResizing);
        }

        Ok(())
    }

    /// Allocates a secret file descriptor based on the configuration and returns the
    /// file descriptor wrapped into a [super::mmap::MappableFd] for easy mapping into
    /// memory.
    ///
    /// This function returns a [super::mmap::MappableFd] and pre-configures the memory mapping
    /// configuration as needed:
    ///
    /// - If [SecretMemfdUsage::shared_memory] is set, then [super::mmap::MapFdConfig::shared] will
    ///   be set. The flag is also set unconditionally when memfd_secret(2) is used, because the
    ///   kernel rejects MAP_PRIVATE mappings of memfd_secret(2) file descriptors (see
    ///   [super::mmap::MapFdConfig::shared])
    /// - If memfd_secret(2) is used, but [memfd_secret_protects_against_resizing()] is false, then
    ///   [super::mmap::MapFdConfig::no_resizing_protection] will be set
    ///
    /// Note that if all three of the conditions hold, then the configuration is insecure and
    /// [Self::validate_config()] will produce [SecretMemfdConfigValidationError::MemfdSecretDoesNotProtectAgainstResizing], which
    /// will be returned wrapped in [SecretMemfdWithConfigError::InvalidConfig]. The three
    /// conditions are:
    ///
    /// - memfd_secret(2) is being used
    /// - [SecretMemfdUsage::shared_memory] is true
    /// - [memfd_secret_protects_against_resizing()] is false
    ///
    /// The close-on-exec (CLOEXEC) file descriptor flag is always set on the
    /// produced file descriptor.
    ///
    /// On the memfd_create(2) backend, the file descriptor is additionally
    /// created with ALLOW_SEALING so it can later be protected against resizing
    /// and it is also sealed non-executable (MFD_NOEXEC_SEAL) where the kernel
    /// supports it (Linux >= 6.3).
    pub fn create(&self) -> Result<MappableFd<OwnedFd>, SecretMemfdWithConfigError> {
        use SecretMemfdConfigValidationError as VE;
        use SecretMemfdMechanism as M;
        use SecretMemfdWithConfigError as E;

        self.validate_config()?;

        let mech = self.mechanism().map_err(VE::FailedToDetectSupport)?;
        let fd = 'fd: {
            match mech {
                // We have to use MemfdCreate; this is the harder case handled below
                M::MemfdCreate => (),
                // The kernel accepts no memfd_secret(2) flag other than O_CLOEXEC
                // Since this is the easy case, we handle it here
                M::MemfdSecret => {
                    break 'fd memfd_secret(MemfdSecretFlags::CLOEXEC)
                        .map_err(E::MemfdSecretError)?;
                }
            };

            use MemfdFlags as F;
            let name = "rosenpass secret memory segment";
            let flags = F::CLOEXEC | F::ALLOW_SEALING;

            // memfd_secret(2) appears to be unsupported; fall back to memfd_create(2)
            match memfd_create(name, flags | F::NOEXEC_SEAL) {
                // Invalid call; probably means that NOEXEC_SEAL is not supported on this kernel
                Err(Errno::INVAL) => (),
                // Valid result, immediately return
                res => break 'fd res.map_err(E::MemfdCreateError)?,
            }

            // NOEXEC_SEAL appears to be unsupported for memfd_create(2); fall back to not using it
            // Allocate without NOEXEC_SEAL and then add the seal against execution later
            let fd = memfd_create(name, flags).map_err(E::MemfdCreateError)?;

            // TODO(hardening): We should emulate NOEXEC_SEAL at some point
            //
            // To this end, we will need to:
            //
            // 1. First ensure that the file descriptor is not executable with fchmod(2)
            // 2. Add the seal using fcntl(2)
            //
            // The fchmod call should be somewhat opportunistic, as it may fail if, by system
            // configuration, the seal has already been added. This is obviously a problem if
            // the fd is marked executable, but it is not an issue if the FD is not executable
            // and the seal is already set. For this reason, we should just check before the
            // fchmod(2) call if the executable bit is already set to the right value.

            // We are finished!
            break 'fd fd;
        };

        // Wrap into MappableFd with the correct configuration
        MappableFd::new(fd, self.map_fd_config()?).ok()
    }

    /// Infers the correct [MapFdConfig] for this [SecretMemfdConfig]
    /// on the current operating system.
    ///
    /// This incorporates information such as:
    ///
    /// - Is the [SecretMemfdUsage::shared_memory] flag set?
    /// - Are memfd_create(2) or memfd_secret(2) used?
    /// - Does memfd_secret(2) support resizing protection?
    pub fn map_fd_config(&self) -> Result<MapFdConfig, SecretMemfdConfigValidationError> {
        use SecretMemfdConfigValidationError as E;

        self.validate_config()?;

        let cfg = MapFdConfig::new();

        let mech = self.mechanism().map_err(E::FailedToDetectSupport)?;
        let mfds_use = matches!(mech, SecretMemfdMechanism::MemfdSecret);

        // Propagate information about whether shared memory is used into the config
        //
        // The shared flag is also set unconditionally for memfd_secret(2) file descriptors:
        // the kernel rejects MAP_PRIVATE mappings of memfd_secret(2) file descriptors with
        // EINVAL (see [super::mmap::MapFdConfig::shared]); for a file descriptor no other
        // process holds, a shared mapping is semantically private
        let cfg = match self.usage.shared_memory || mfds_use {
            false => cfg,
            true => cfg.set_shared(),
        };

        // If necessary, disable protection against resizing (if not supported)
        let mfds_prot_resize =
            memfd_secret_protects_against_resizing().map_err(E::FailedToDetectSupport)?;
        let cfg = match mfds_use && !mfds_prot_resize {
            false => cfg,
            true => cfg.disable_resizing_protection(),
        };

        Ok(cfg)
    }
}

/// Create a secret memory file descriptor using the default policy
///
/// Shorthand for
/// [`SecretMemfdConfig::new()`] followed by [`SecretMemfdConfig::create()`]
pub fn memfd_for_secrets_with_default_policy()
-> Result<MappableFd<OwnedFd>, SecretMemfdWithConfigError> {
    SecretMemfdConfig::new().create()
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsFd;

    use super::*;

    #[test]
    fn test_created_secret_memfds_are_close_on_exec() {
        fn assert_close_on_exec<Fd: AsFd>(fd: &Fd) {
            let fd_flags = rustix::io::fcntl_getfd(fd).expect("fcntl(F_GETFD) failed");
            assert!(fd_flags.contains(rustix::io::FdFlags::CLOEXEC));
        }

        // memfd_create(2) backend
        let cfg = SecretMemfdConfig {
            policy: SecretMemfdPolicy::DisableMemfdSecret,
            ..SecretMemfdConfig::new()
        };
        assert_close_on_exec(&cfg.create().expect("memfd_create(2) failed"));

        // memfd_secret(2) backend, on systems that support it
        if memfd_secret_support()
            .expect("probing memfd_secret(2) support failed")
            .is_ok()
        {
            let cfg = SecretMemfdConfig {
                policy: SecretMemfdPolicy::UseMemfdSecret,
                ..SecretMemfdConfig::new()
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

    /// Regression test: the default (local-usage) configuration must produce a
    /// memfd_secret(2) file descriptor that can actually be mapped. The kernel
    /// rejects MAP_PRIVATE mappings of memfd_secret(2) file descriptors with EINVAL
    /// (secretmem_mmap() in mm/secretmem.c), so [SecretMemfdConfig::create()] must
    /// always set [super::mmap::MapFdConfig::shared] when memfd_secret(2) is used,
    /// even when [SecretMemfdUsage::shared_memory] is not set.
    ///
    /// Skips cleanly on systems where memfd_secret(2) is unavailable (kernel too
    /// old, disabled at boot, or blocked by seccomp/LSM policy); on systems with
    /// support, the default (opportunistic) policy selects memfd_secret(2) for
    /// local usage.
    #[test]
    fn test_default_policy_memfd_secret_is_shared_and_mappable() {
        if !matches!(memfd_secret_support(), Ok(Ok(_))) {
            return;
        }

        let mfd = SecretMemfdConfig::new()
            .create()
            .expect("creating a secret memfd with the default policy failed");
        assert!(
            mfd.config().shared,
            "create() must set MapFdConfig::shared for memfd_secret(2) file descriptors"
        );

        let cfg = mfd.config().resize_on_mmap(4096);
        let seg = mfd
            .with_config(cfg)
            .mmap()
            .expect("mapping a default-policy memfd_secret(2) file descriptor failed");
        assert_eq!(seg.len(), 4096);
    }
}
