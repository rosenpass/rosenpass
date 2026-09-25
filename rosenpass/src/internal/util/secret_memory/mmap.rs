//! This module takes care of allocating memory segments for
//! file descriptors created with [super::fd::memfd_for_secrets_with_default_policy]
//! and anonymous memory segments

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::ptr::null_mut;

use rustix::fs::{SealFlags, fcntl_add_seals, fcntl_get_seals};
use rustix::io::Errno;

use crate::internal::util::convert::TryIntoTypeExt;
use crate::internal::util::functional::SideffectExt;
use crate::internal::util::int::u64uint::{MAX_U64_IN_USIZE, U64USize};
use crate::internal::util::mem::CopyExt;
use crate::internal::util::result::OkExt;

use crate::internal::util::mem::DiscardResultExt;
use crate::internal::util::secret_memory::fd::{
    SecretMemfdConfig, SecretMemfdConfigValidationError, memfd_secret_protects_against_resizing,
};

/// Size of the memory mapping for [MappableFd]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MMapSizePolicy {
    /// Size is checked against this particular value; [MappableFd::mmap] will check the
    /// size of the underlying data and raise an error if the size of data and this value
    /// do not match
    Checked(u64),
    /// Size is defined to be this particular value; [MappableFd::mmap] will explicitly resize
    /// the underlying file descriptor to be this particular size when called.
    Resize(u64),
}

impl MMapSizePolicy {
    /// The numeric value of the size
    pub fn size_value(&self) -> u64 {
        match *self {
            Self::Checked(v) => v,
            Self::Resize(v) => v,
        }
    }
}

/// Configuration for [MappableFd::mmap]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MapFdConfig {
    /// The memory region can not be read from
    pub unreadable: bool,
    /// The memory region can not be written to
    pub immutable: bool,
    /// The memory region is shared-memory; other mappings of the same
    /// region within and outside this process can see the modifications
    /// to the memory region (as long as they also set the shared flag)
    ///
    /// memfd_secret(2) file descriptors require a shared mapping: the kernel rejects
    /// MAP_PRIVATE mappings of memfd_secret(2) file descriptors with EINVAL
    /// (secretmem_mmap() in mm/secretmem.c), so this flag is kernel-enforced for such
    /// file descriptors. For a file descriptor no other process holds, a shared mapping
    /// is semantically private; [SecretMemfdConfig::create()] therefore always
    /// sets this flag when memfd_secret(2) is used.
    ///
    /// Note that when this flag is used together with [Self::no_resizing_protection],
    /// then the configuration is vulnerable to the attack described in [super::fd::memfd_secret_support()].
    ///
    /// This insecure configuration will not be rejected as it may still be useful in some
    /// scenarios where the other process is trusted.
    ///
    /// When using [SecretMemfdConfig::create()], this flag and [Self::no_resizing_protection] are
    /// automatically configured.
    pub shared: bool,
    /// Whether the file descriptor should be protected against resizing
    ///
    /// Note that when this flag is used together with [Self::shared],
    /// then the configuration is vulnerable to the attack described in [super::fd::memfd_secret_support()].
    ///
    /// This insecure configuration will not be rejected as it may still be useful in some
    /// scenarios where the other process is trusted.
    ///
    /// Note that when the file descriptor used for allocation is a memfd_secret(2),
    /// this flag MUST be set when [super::fd::memfd_secret_protects_against_resizing()] is false (this is
    /// the case on some systems) and it MUST NOT be set when [super::fd::memfd_secret_protects_against_resizing()]
    /// is true. [MappableFd::mmap] enforces this constraint for memfd_secret(2) file
    /// descriptors only; for other file descriptors, the flag merely selects whether
    /// resizing protection (sealing) is requested.
    ///
    /// When using [SecretMemfdConfig::create()], this flag and [Self::shared] are
    /// automatically configured.
    pub no_resizing_protection: bool,
    /// How [MappableFd::mmap] will determine the size to be used for the mapping
    ///
    /// You should usually set this value through [Self::set_size_policy],
    /// [Self::expected_size], or [Self::resize_on_mmap].
    pub size_policy: Option<MMapSizePolicy>,
}

impl MapFdConfig {
    /// New MapFdConfig with all settings turned off
    ///
    /// You still must set [Self::size_policy], otherwise [MappableFd::mmap] will raise
    /// an error when called
    pub const fn new() -> Self {
        MapFdConfig {
            unreadable: false,
            immutable: false,
            shared: false,
            no_resizing_protection: false,
            size_policy: None,
        }
    }

    /// Alias for [SecretMemfdConfig::map_fd_config()]
    pub fn from_secret_memfd_config(
        cfg: &SecretMemfdConfig,
    ) -> Result<Self, SecretMemfdConfigValidationError> {
        cfg.map_fd_config()
    }

    /// New MapFdConfig with shared memory turned on
    pub const fn shared_memory() -> Self {
        Self::new().set_shared()
    }

    /// Set the [Self::unreadable] flag
    pub const fn set_unreadable(&self) -> Self {
        let mut r = *self;
        r.unreadable = true;
        r
    }

    /// Set the [Self::immutable] flag
    pub const fn set_immutable(&self) -> Self {
        let mut r = *self;
        r.immutable = true;
        r
    }

    /// Set the [Self::shared] flag
    pub const fn set_shared(&self) -> Self {
        let mut r = *self;
        r.shared = true;
        r
    }

    /// Set the [Self::no_resizing_protection] flag
    pub const fn disable_resizing_protection(&self) -> Self {
        let mut r = *self;
        r.no_resizing_protection = true;
        r
    }

    /// Create a [MappableFd] instance with this configuration
    pub fn mappable_fd<Fd: AsFd>(&self, fd: Fd) -> MappableFd<Fd> {
        MappableFd::new(fd, self.copy())
    }

    /// Calculate [rustix::mm::ProtFlags] for this configuration
    pub const fn mmap_prot(&self) -> rustix::mm::ProtFlags {
        use rustix::mm::ProtFlags as P;

        let p_read = match self.unreadable {
            true => P::empty(),
            false => P::READ,
        };

        let p_write = match self.immutable {
            true => P::empty(),
            false => P::WRITE,
        };

        p_read.union(p_write)
    }

    /// Calculate [rustix::mm::MapFlags] for this configuration
    pub const fn mmap_flags(&self) -> rustix::mm::MapFlags {
        use rustix::mm::MapFlags as M;
        match self.shared {
            true => M::SHARED,
            false => M::PRIVATE,
        }
    }

    /// Set [Self::size_policy] to the given value
    pub const fn set_size_policy(&self, size_policy: MMapSizePolicy) -> Self {
        let mut r = *self;
        r.size_policy = Some(size_policy);
        r
    }

    /// Set [Self::size_policy] to [MMapSizePolicy::Checked] with the given value
    pub const fn expected_size(&self, size: u64) -> Self {
        self.set_size_policy(MMapSizePolicy::Checked(size))
    }

    /// Set [Self::size_policy] to [MMapSizePolicy::Resize] with the given value
    pub const fn resize_on_mmap(&self, size: u64) -> Self {
        self.set_size_policy(MMapSizePolicy::Resize(size))
    }
}

/// Errors for [MappableFd::mmap()] caused by invalid [MapFdConfig] configurations
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MMapInvalidConfigError {
    /// Mismatch between [MapFdConfig::disable_resizing_protection]
    /// and [super::fd::memfd_secret_protects_against_resizing()]
    #[error("\
        When mapping a memfd_secret(2) into memory, whether protection against \
        resizing is enabled is fully determined by the system. In this scenario, \
        the setting in MapFdConfig::no_resizing_protection merely acts as a \
        safety check to make sure that the developer request matches the system setting. \
        During the call to MappableFd::mmap, we check whether these settings match. \
        On this system, protection against resizing is {}, but the developer requested that \
        the protection be {}. \
        \n protection_enabled_by_system = {}; \
        \n protection_requested = {}; \
        \n memfd_secret_protects_against_resizing() = {}; \
        \n MapFdConfig::disable_resizing_protection = {};",
        match protection_enabled_by_system {
            false => "DISABLED",
            true => "ENABLED",
        },
        match protection_requested {
            false => "DISABLED",
            true => "ENABLED",
        },
        protection_enabled_by_system,
        protection_requested,
        match memfd_secret_protects_against_resizing() {
            Ok(true) => "true",
            Ok(false) => "false",
            Err(_)  => "<ERROR>",
        },
        !protection_requested,
    )]
    IncorrectResizingProtectionSetting {
        /// Whether the system protects memfd_secret(2) file descriptors against resizing
        protection_enabled_by_system: bool,
        /// Whether protection against resizing was requested
        /// (the inverse of [MapFdConfig::no_resizing_protection])
        protection_requested: bool,
    },
    /// When memory mapping memfd_secret(2) file descriptors, [MapFdConfig::shared] MUST be used
    /// as MAP_PRIVATE is not supported by the operating system.
    #[error(
        "\
        When mapping a memfd_secret(2) into memory, MAP_PRIVATE can not be used
        and usage of MAP_SHARED is mandatory. Please always set MapFdConfig::shared
        when memory mapping memfd_secret(2) based file descriptors, even if the file
        is not actually shared between processes.\
    "
    )]
    MapSharedNeededForMemfdSecret,
}

/// Errors for sealing memfd_create(2) file descriptors against resizing in [MappableFd::mmap()]
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemfdCreateSealError {
    /// The file descriptor is already sealed against adding further seals while
    /// still missing seals we need to add
    #[error(
        "Tried to seal the underlying file descriptor against being grown/shrunken, but the file descriptor already carried {:?} while missing {:?}, so the seals could not be added.",
        SealFlags::SEAL,
        missing
    )]
    PresealedWithMissingSeals {
        /// The seals that still needed to be added
        missing: SealFlags,
    },
    /// The file descriptor was resized while it was being sealed against resizing
    #[error(
        "\
        Tried to seal the underlying file descriptor against being grown/shrunken, but during the process, \
        the file descriptor was resized from the expected size of {} to {}. The file descriptor is now the \
        wrong size, but since it has been sealed, we can no longer resize it.",
        expected_size,
        actual_size
    )]
    ResizeRace {
        /// The size the file descriptor was expected to have
        expected_size: u64,
        /// The size the file descriptor actually had after sealing
        actual_size: u64,
    },
    /// One of the fcntl(2) system calls used for sealing failed
    #[error(
        "Tried to seal the underlying file descriptor against being grown/shrunken, but one of the fcntl(2) system calls failed: {0}"
    )]
    SystemError(rustix::io::Errno),
    /// Adding the seals was retried many times, but never succeeded
    #[error(
        "Tried to seal the underlying file descriptor against being grown/shrunken many times, but we never succeeded. This likely is a bug"
    )]
    RetriesAborted,
}

/// Error returned by MappableFd::mmap
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MMapError {
    /// Invalid mapping configuration; see [MMapInvalidConfigError]
    #[error("Could not map file descriptor into memory: {0}")]
    InvalidConfig(#[from] MMapInvalidConfigError),
    /// Error converting from u64 to usize
    #[error("Requested memory map of size {requested_len} but maximum supported size is {max_supported_len}. \
        This is a low level error that usually arises on architectures where the integer type usize ({} bytes) can not \
        represent all values in u64 ({} bytes). Are you possibly on a 32-bit CPU architecture requesting a buffer bigger than 4 GB?\n\
          Error: {err:?}",
        (usize::BITS as f64)/8f64, (u64::BITS as f64)/8f64
    )]
    OutOfBounds {
        /// Underlying error
        err: <u64 as TryInto<U64USize>>::Error,
        /// The size of the memory map requested
        requested_len: u64,
        /// Maximum supported size
        max_supported_len: u64,
    },
    /// Tried to map a file descriptor into memory, but the size policy was never set. Developer
    /// error.
    #[error(
        "Tried to map a file descriptor into memory, but the size policy was never set. This is a developer error."
    )]
    MissingSizePolicy,
    /// Zero-length memory mappings are not supported
    #[error(
        "Tried to map file descriptor into memory with a size of zero; the kernel rejects zero-length mappings with EINVAL"
    )]
    ZeroSize,
    /// fstat(2)/fstatfs(2) system call failed
    #[error("Tried to map file descriptor into memory, but failed to determine the size and type of the file descriptor (fstat(2)/fstatfs(2) failed): {}", .0)]
    CouldNotDetermineFileDescriptorInfo(rustix::io::Errno),
    /// Mismatch between expected and actual size of the file descriptor
    #[error(
        "Tried to map file descriptor into memory with expected size {expected:?}, but instead we found that the true size is {actual:?}"
    )]
    IncorrectSize {
        /// Expected file descriptor size (given by caller)
        expected: u64,
        /// Actual file descriptor size
        actual: u64,
    },
    /// Negative size reported by fstat(2)
    #[error(
        "Tried to determine the size of the underlying file descriptor, but the reported size ({size}) is negative: {err:?}"
    )]
    InvalidSize {
        /// Underlying error
        err: <i64 as TryInto<u64>>::Error,
        /// Reported size of the file descriptor
        size: i64,
    },
    /// ftruncate(2) system call failed
    #[error("Tried to resize the underlying file descriptor, but failed: {:?}", .0)]
    ResizeError(rustix::io::Errno),
    /// mmap(2) system call failed
    #[error("Tried to map file descriptor into memory, but mmap(2) system call failed: {:?}", .0)]
    MMapError(rustix::io::Errno),
    /// mlock(2) system call failed
    ///
    /// mlock(2) counts against the RLIMIT_MEMLOCK resource limit; see
    /// [MappableFd::mmap] for deployment notes
    #[error("Tried to lock the file-descriptor based allocation into memory, but the mlock(2) system call failed: {}", .0)]
    MLockError(rustix::io::Errno),
    /// Sealing the file descriptor against resizing failed; see [MemfdCreateSealError]
    #[error(
        "Tried to seal file descriptor against being grown/shrunken before mapping into memory: {0}"
    )]
    SealError(#[from] MemfdCreateSealError),
}

/// Handle mapping a file descriptor into memory
pub struct MappableFd<Fd: AsFd> {
    /// The file descriptor this struct refers to
    fd: Fd,
    /// The configuration for mmap
    config: MapFdConfig,
}

impl<Fd: AsFd> AsFd for MappableFd<Fd> {
    fn as_fd(&self) -> BorrowedFd<'_> {
        self.fd.as_fd()
    }
}

impl<Fd: AsFd> AsRawFd for MappableFd<Fd> {
    fn as_raw_fd(&self) -> RawFd {
        self.as_fd().as_raw_fd()
    }
}

impl<Fd: AsFd> MappableFd<Fd> {
    /// Create a [MappableFd] using the default configuration ([MapFdConfig])
    pub fn from_fd(fd: Fd) -> Self {
        Self::new(fd, MapFdConfig::default())
    }

    /// Create a new [MappableFd] for an existing file descriptor
    pub fn new(fd: Fd, config: MapFdConfig) -> Self {
        Self { fd, config }
    }

    /// Extract the underlying file descriptor
    pub fn into_fd(self) -> Fd {
        self.fd
    }

    /// Access the [MapFdConfig] associated with Self
    pub fn config(&self) -> MapFdConfig {
        self.config
    }

    /// Access the [MapFdConfig] associated with Self
    pub fn config_mut(&mut self) -> &mut MapFdConfig {
        &mut self.config
    }

    /// Modify the [MapFdConfig] associated with Self, chainable
    pub fn with_config(mut self, config: MapFdConfig) -> Self {
        self.config = config;
        self
    }

    /// Map the file into memory
    ///
    /// # Determining the size of the mapping
    ///
    /// Before calling this function, [MapFdConfig::size_policy] must be set.
    ///
    /// Note that [Self::from_fd] and [Self::new] still allow you to create a [Self] with
    /// [MapFdConfig::size_policy] set to [None]; the size policy must be configured before
    /// calling this function, otherwise [MMapError::MissingSizePolicy] is raised.
    ///
    /// Auto-detection of the size is deliberately not implemented, as it's crucial to validate
    /// the size of the data being mapped into memory somehow; otherwise, the party that created
    /// the file descriptor can trigger a denial-of-service attack against our process by
    /// allocating an excessively large, sparse file. If you implement size auto-detection
    /// facilities, you should still enforce some bounds on the size.
    ///
    /// # Locking pages into memory
    ///
    /// The mapped pages are locked into memory with mlock(2) unless the mapping is
    /// unreadable or the file descriptor is a memfd_secret(2). mlock(2) counts against
    /// the RLIMIT_MEMLOCK resource limit; production deployments must configure the
    /// limit, otherwise the mapping fails fatally with [MMapError::MLockError].
    ///
    /// # memfd_secret(2) based mappings
    ///
    /// Secretmem pages are fault-allocated lazily: mmap(2) succeeding does not
    /// guarantee that the pages can actually be populated; if the fault-time
    /// accounting fails, a later access can still fail fatally (SIGBUS or
    /// SIGKILL depending on the fault path). mlock(2) is skipped for
    /// memfd_secret(2) file descriptors: secretmem pages are never swapped by
    /// design, so locking them is unnecessary.
    ///
    /// # Safety
    ///
    /// If there exist any Rust references referring to the memory region, or if you subsequently create a Rust reference referring to the resulting region, it is your responsibility to ensure that the Rust reference invariants are preserved, including ensuring that the memory is not mutated in a way that a Rust reference would not expect.
    pub fn mmap(&self) -> Result<MappedSegment, MMapError> {
        use rustix::mm::mmap;

        // Error types used
        use MMapError as E;
        use MMapInvalidConfigError as EC;
        use MemfdCreateSealError as ES;

        // Configuration options
        let prot = self.config().mmap_prot();
        let flags = self.config().mmap_flags();

        // Determine the size policy used
        let size_policy = match self.config().size_policy {
            Some(v) => v,
            None => return Err(E::MissingSizePolicy),
        };

        // Prepare file information
        let mut stat = Quickstat::new(self.fd.as_fd());

        // Ensure that the fstatfs(2) call happens now so we report errors early
        // we will need the information whether the file descriptor is memfd_secret(2) later
        stat.is_memfd_secret()?.discard_result();

        // memfd_secret(2) does not support MAP_PRIVATE in mmap(2)
        if stat.is_memfd_secret()? && !self.config.shared {
            Err(EC::MapSharedNeededForMemfdSecret)?;
        }

        // Validate that the resizing protection settings match the mandatory settings
        // with memfd_secret(2)
        let resize_protection_requested = !self.config.no_resizing_protection;
        if stat.is_memfd_secret()? {
            let resize_protection_enabled =
                memfd_secret_protects_against_resizing().map_err(ES::SystemError)?;
            if resize_protection_requested != resize_protection_enabled {
                Err(EC::IncorrectResizingProtectionSetting {
                    protection_enabled_by_system: resize_protection_enabled,
                    protection_requested: resize_protection_requested,
                })?;
            }
        }

        // Seal sets used when sealing
        //
        // - SRESIZE (F_SEAL_SHRINK | F_SEAL_GROW): The required seal set;
        //   needed to prevent adversarial users in shared memory from
        //   triggering SIGSEGV/SIGBUS (invalid memory access) by truncating
        //   the shared file descriptor
        // - F_SEAL_SEAL is deliberately NOT installed: third parties holding
        //   the same file descriptor can only ever ADD seals, never remove
        //   ours, so our resize protection cannot be weakened; leaving the
        //   seal set open permits installing further seals later (e.g.
        //   F_SEAL_FUTURE_WRITE)
        // - SSEAL (F_SEAL_SEAL): Never installed; used only to detect file
        //   descriptors that are already sealed against adding further seals
        use SealFlags as FS;
        const SRESIZE: SealFlags = FS::SHRINK.union(FS::GROW);
        const SSEAL: SealFlags = FS::SEAL;

        // Check early whether it will be impossible to set the right seals on the file descriptor,
        // so we won't modify the file descriptor by resizing it in this case.
        //
        // Skipped entirely when resize protection is not requested: the sealing loop below
        // no-ops in that case, and the fcntl(2) sealing interface is not even implemented
        // for regular (non-memfd) files (fcntl_get_seals fails with EINVAL)
        if resize_protection_requested && !stat.is_memfd_secret()? {
            let current_seals = fcntl_get_seals(self).map_err(ES::SystemError)?;
            let missing = SRESIZE.difference(current_seals);

            // Unable to add the missing seals, FD is already sealed against adding further seals
            if current_seals.contains(SSEAL) && !missing.is_empty() {
                Err(ES::PresealedWithMissingSeals { missing })?;
            }
        }

        // Retrieve the expected size, raising an error if the
        // requested_size can not be represented as usize (this should never happen in general,
        // but it could conceivably be thrown on 32 bit systems when very large mappings (>= 4GB)
        // are requested
        let requested_size = size_policy
            .size_value()
            .try_into_type::<U64USize>()
            .map_err(|err| {
                let requested_size = err.given_value().copy();
                let max_supported_len = MAX_U64_IN_USIZE;
                E::OutOfBounds {
                    err,
                    requested_len: requested_size,
                    max_supported_len,
                }
            })?;

        // The kernel rejects zero-length mappings with EINVAL; reject them
        // up front, BEFORE any ftruncate(2) below, so a failed mmap never
        // leaves the underlying file descriptor truncated as a side effect
        if requested_size.u64() == 0 {
            return Err(E::ZeroSize);
        }

        // Resize the file descriptor if requested and necessary
        use MMapSizePolicy as P;
        match size_policy {
            P::Resize(_) => {
                let actual_size = stat.size()?;
                if requested_size.u64() != actual_size {
                    rustix::fs::ftruncate(self, requested_size.u64()).map_err(E::ResizeError)?;
                }
            }
            P::Checked(_) => {
                let expected = requested_size.u64();
                let actual = stat.size()?;
                if expected != actual {
                    return Err(E::IncorrectSize { expected, actual });
                }
            }
        }

        // Protect against future resizing
        let mut seal_ctr: usize = usize::MAX;
        let mut prev_seals: Option<SealFlags> = None;
        'seal: loop {
            // Do not protect against resizing if this is disabled
            if !resize_protection_requested {
                break 'seal;

            // No active steps needed to protect memfd_secret based file descriptors
            // against resizing
            } else if stat.is_memfd_secret()? {
                break 'seal;
            }

            // Increment the loop counter
            seal_ctr = seal_ctr.overflowing_add(1).0;

            // Abort this loop after too many failed attempts just to be safe
            if seal_ctr >= 16 {
                Err(ES::RetriesAborted)?;
            }

            // Add the seals
            //
            // The call succeeding and failing with permission denied are both
            // handled the same way: fetch the list of seals below and check
            // what seals we actually got
            //
            // Permission denied could happen because F_SEAL_SEAL raced in
            // concurrently (detected via the seal set below and reported as
            // PresealedWithMissingSeals), or because the file descriptor is
            // not writable — adding seals requires a writable file descriptor;
            // that case can never make progress and is detected by the
            // no-progress check below
            let add_denied = match fcntl_add_seals(self, SRESIZE) {
                Ok(()) => false,
                Err(Errno::PERM) => true,
                // Other error; just propagate this error to the function caller
                Err(errno) => return Err(ES::SystemError(errno))?,
            };

            // Figure out what seals are set and which ones we need to add
            let current_seals = fcntl_get_seals(self).map_err(ES::SystemError)?;
            let missing = SRESIZE.difference(current_seals);

            // Unable to add the missing seals, FD is already sealed against adding further seals
            if current_seals.contains(SSEAL) && !missing.is_empty() {
                Err(ES::PresealedWithMissingSeals { missing })?;
            }

            // Adding seals was denied and the seal set did not change since the
            // last attempt: no progress is possible (e.g. the file descriptor
            // is not writable), so retrying would merely spin until the retry
            // limit; report the persistent permission error instead
            if add_denied && prev_seals == Some(current_seals) {
                Err(ES::SystemError(Errno::PERM))?;
            }
            prev_seals = Some(current_seals);

            // Missing seals, but not sealed against further seals. Try to add the seals we need.
            if !missing.is_empty() {
                continue 'seal;
            }

            // All the seals are present; check the size of the file descriptor again
            // just to make sure that the size is correct. If it's not correct, we raise
            // an error
            let (expected_size, actual_size) = (requested_size.u64(), Quickstat::new(self).size()?);
            if expected_size != actual_size {
                Err(ES::ResizeRace {
                    expected_size,
                    actual_size,
                })?;
            }

            // Sealing successful; now aborting
            break 'seal;
        }

        // SAFETY:
        //
        // * `ptr` is NULL, so mmap chooses a fresh mapping; rustix's
        //   non-null input-pointer provenance requirement does not apply.
        // * We don't use MAP_FIXED, so no existing Rust allocation/reference
        //   is replaced.
        let len = requested_size.usize();
        let ptr = unsafe { mmap(null_mut(), len, prot, flags, self, 0) };
        let ptr = ptr.map_err(E::MMapError)?;
        let ptr = unsafe { MappedSegment::from_raw_parts(ptr.cast(), len) };

        // mlock(2) the memory region into memory (prevent swapping)
        //
        // We do not mlock(2) the memory in two cases:
        //
        // - The backing file descriptor is memfd_secret(2), as the semantics of memfd_secret(2)
        //   automatically lock all memfd_secret(2) derived pages into memory
        // - The mapping is unreadable, in which case [rustix::mm::mlock] documents
        //   that mlock is not supported on unreadable mappings
        //
        // SAFETY:
        //
        // * The pointer came directly from mmap, so it retains the mapping's
        //   provenance.
        // * mmap returns a page-aligned mapping address.
        // * POSIX mmap operates on whole pages, so the page-rounded range
        //   touched by mlock is part of this mapping.
        // * PROT_READ makes the range readable, satisfying rustix's
        //   documented mlock precondition. PROT_READ is set, because we check for
        //   `self.config().unreadable` explicitly.
        if !stat.is_memfd_secret()? && !self.config().unreadable {
            let res = unsafe { rustix::mm::mlock(ptr.ptr().cast(), len) };
            res.map_err(E::MLockError)?;
        }

        Ok(ptr)
    }
}

/// Represents exclusive ownership of a memory segment mapped into memory
///
/// Automatically unmaps the memory segment as this goes out of scope
///
/// # Panic
///
/// If the munmap(2) call fails, the destructor will panic; if this happens
/// while the process is already unwinding due to another panic, the process
/// aborts. You can avoid this and use explicit error handling by calling
/// [Self::unmap] instead
#[derive(Debug)]
pub struct MappedSegment {
    /// The location of the memory segment
    ptr: *mut u8,
    /// Length of the segment in bytes
    len: usize,
}

unsafe impl Send for MappedSegment {}

impl MappedSegment {
    /// Construct a new [Self] from a pointer and a length
    ///
    /// `ptr` is the address of the memory segment and `len` is its length in bytes
    ///
    /// # Safety
    ///
    /// Dropping the returned [Self] unmaps the memory region with munmap(2);
    /// the caller must guarantee all of the following, both for the region to
    /// be usable and for the destructor not to fail (which would panic):
    ///
    /// - `ptr` is the page-aligned start address of a memory mapping, as
    ///   returned by mmap(2)
    /// - `len` is greater than zero and `ptr + len` does not overflow the
    ///   address space
    /// - the entire region `ptr .. ptr + len` is part of that same, currently
    ///   valid mapping: any pointer `ptr.add(n)` with `n < len` is a valid
    ///   pointer; see the `# Safety` section in [std::ptr]
    /// - the mapping is exclusively owned by the returned [Self]: no other
    ///   handle (such as another [MappedSegment]) refers to the same mapping,
    ///   and no other code unmaps or remaps the region
    /// - the mapping remains valid for the entire lifetime of the returned
    ///   [Self]
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Decompose a MappedSegment into its raw components: pointer and length
    pub fn into_raw_parts(self) -> (*mut u8, usize) {
        let r = (self.ptr(), self.len());
        std::mem::forget(self);
        r
    }

    /// The location of the memory segment
    pub fn ptr(&self) -> *mut u8 {
        self.ptr
    }

    /// Length of the segment in bytes
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.len
    }

    /// Release the memory segment
    ///
    /// Compared to using the destructor which panics if unmapping fails, this allows explicit error handling to be used.
    ///
    /// If this returns an error, the memory segment has not been freed. The values from
    /// [Self::into_raw_parts()] are returned as part of the error value so the caller has
    /// some chance to free the memory some other way (or to leak it if they so choose)
    pub fn unmap(self) -> Result<(), (rustix::io::Errno, *mut u8, usize)> {
        let (ptr, len) = self.into_raw_parts();
        let res = unsafe { rustix::mm::munmap(ptr.cast(), len) };
        res.map_err(|errno| (errno, ptr, len))
    }
}

impl Drop for MappedSegment {
    fn drop(&mut self) {
        let mut owned = MappedSegment {
            ptr: null_mut(),
            len: 0,
        };
        std::mem::swap(self, &mut owned);
        if let Err((errno, _ptr, _len)) = owned.unmap() {
            panic!("Failed to unmap MappedSegment: {errno:?}")
        }
    }
}

/// Helper for calling fstat in [MappableFd::mmap()]
#[derive(Copy, Clone, Debug)]
struct Quickstat<Fd: AsFd> {
    /// The file descriptor being interrogated
    fd: Fd,
    /// Cached fstat(2) result
    stat: Option<rustix::fs::Stat>,
    /// Cached fstatfs(2) result
    statfs: Option<rustix::fs::StatFs>,
}

impl<Fd: AsFd> Quickstat<Fd> {
    /// New [Quickstat] wrapping the given file descriptor; no system calls
    /// have been issued yet, results are cached on first use
    pub fn new(fd: Fd) -> Self {
        Self {
            fd,
            stat: None,
            statfs: None,
        }
    }

    /// fstat(2) the file descriptor (cached)
    pub fn stat(&mut self) -> Result<rustix::fs::Stat, MMapError> {
        if let Some(stat) = self.stat {
            return Ok(stat);
        }

        rustix::fs::fstat(self.fd.as_fd())
            .map_err(MMapError::CouldNotDetermineFileDescriptorInfo)?
            .sideeffect(|stat| {
                self.stat = Some(*stat);
            })
            .ok()
    }

    /// fstatfs(2) the file descriptor (cached)
    pub fn statfs(&mut self) -> Result<rustix::fs::StatFs, MMapError> {
        if let Some(statfs) = self.statfs {
            return Ok(statfs);
        }

        rustix::fs::fstatfs(self.fd.as_fd())
            .map_err(MMapError::CouldNotDetermineFileDescriptorInfo)?
            .sideeffect(|statfs| {
                self.statfs = Some(*statfs);
            })
            .ok()
    }

    /// The size of the file descriptor according to fstat(2)
    pub fn size(&mut self) -> Result<u64, MMapError> {
        let size = self.stat()?.st_size;
        size.try_into()
            .map_err(|err| MMapError::InvalidSize { err, size })
    }

    /// Whether the file descriptor is a memfd_secret(2) file descriptor,
    /// determined via the fstatfs(2) f_type magic
    pub fn is_memfd_secret(&mut self) -> Result<bool, MMapError> {
        use crate::internal::util::rustix::IsMemfdSecretExt;
        self.statfs()?.is_memfd_secret().ok()
    }
}
#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use rustix::fs::MemfdFlags;
    use rustix::io::Errno;

    use super::*;
    use crate::internal::util::rustix::memfd_create;

    /// Create a memfd for testing via the crate's own memfd helpers
    ///
    /// The memfd is created with ALLOW_SEALING, matching the file descriptors
    /// produced by [crate::internal::util::secret_memory::fd::SecretMemfdConfig::create()]:
    /// [MappableFd::mmap] seals file descriptors against resizing by default and
    /// rejects file descriptors whose seals cannot be amended (a memfd created
    /// without ALLOW_SEALING is pre-sealed with F_SEAL_SEAL by the kernel).
    ///
    /// Returns [None] — skipping the test gracefully — if memfd_create(2) is
    /// unavailable on this system (ENOSYS: kernel too old; EPERM/EACCES:
    /// blocked by seccomp/LSM policy)
    fn test_memfd() -> Option<OwnedFd> {
        match memfd_create(
            "rosenpass mmap.rs unit test",
            MemfdFlags::CLOEXEC | MemfdFlags::ALLOW_SEALING,
        ) {
            Ok(fd) => Some(fd),
            Err(Errno::NOSYS | Errno::PERM | Errno::ACCESS) => None,
            Err(e) => panic!("Unexpected error probing memfd_create(2): {e:?}"),
        }
    }

    /// A non-shared mapping must be performed with
    /// MAP_PRIVATE, not with empty flags.
    ///
    /// Linux requires exactly one of MAP_PRIVATE / MAP_SHARED; flags = 0 makes
    /// every mmap(2) call fail with EINVAL.
    #[test]
    fn test_private_memfd_mapping_succeeds() {
        // Flags computation: exactly one of MAP_PRIVATE / MAP_SHARED is set
        assert_eq!(
            MapFdConfig::new().mmap_flags(),
            rustix::mm::MapFlags::PRIVATE
        );
        assert_eq!(
            MapFdConfig::shared_memory().mmap_flags(),
            rustix::mm::MapFlags::SHARED
        );

        let Some(fd) = test_memfd() else {
            return;
        };

        // MapFdConfig::new() has shared == false; mapping must succeed.
        // This syscall-level assertion exercises the MAP_PRIVATE selection
        // end-to-end.
        let seg = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("Privately mapping a memfd (MAP_PRIVATE) failed");
        assert_eq!(seg.len(), 4096);
    }

    /// A zero-length mapping must be rejected up front, WITHOUT performing
    /// the ftruncate(2) of the Resize size policy first: a failed mmap must
    /// not leave the file descriptor truncated as a side effect
    #[test]
    fn test_zero_length_mapping_rejected_without_truncating_fd() {
        let Some(fd) = test_memfd() else {
            return;
        };

        // Give the fd a nonzero size so a truncating Resize(0) on the error
        // path would be observable via fstat
        rustix::fs::ftruncate(&fd, 4096).expect("ftruncate(2) failed");
        let size_of = || Quickstat::new(&fd).size().unwrap();
        assert_eq!(size_of(), 4096);

        for cfg in [
            MapFdConfig::new().resize_on_mmap(0),
            MapFdConfig::new().expected_size(0),
        ] {
            let res = cfg.mappable_fd(&fd).mmap();
            assert!(
                matches!(res, Err(MMapError::ZeroSize)),
                "zero-length mapping must be rejected, got: {res:?}"
            );
            assert_eq!(
                size_of(),
                4096,
                "fd must not be truncated on the error path"
            );
        }

        // Checked(0) on a fresh, size-0 fd passes the size comparison and
        // must still be rejected by the zero-length check
        let Some(fd2) = test_memfd() else {
            return;
        };
        let res = MapFdConfig::new().expected_size(0).mappable_fd(&fd2).mmap();
        assert!(matches!(res, Err(MMapError::ZeroSize)));
    }

    /// Map a memfd read-write, write bytes through the mapping, read them
    /// back; a private mapping must not write through to the underlying file
    #[test]
    fn test_private_mapping_write_and_read_back() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let data = [0xA5u8; 64];
        let seg = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("private RW mapping failed");

        // The mapping starts zeroed
        let mut buf = [0xFFu8; 64];
        unsafe {
            seg.ptr()
                .copy_to_nonoverlapping(buf.as_mut_ptr(), buf.len())
        };
        assert_eq!(buf, [0u8; 64]);

        // Write bytes through the mapping and read them back
        unsafe {
            seg.ptr()
                .copy_from_nonoverlapping(data.as_ptr(), data.len())
        };
        let mut buf = [0u8; 64];
        unsafe {
            seg.ptr()
                .copy_to_nonoverlapping(buf.as_mut_ptr(), buf.len())
        };
        assert_eq!(buf, data);

        // MAP_PRIVATE: the writes must NOT propagate to the underlying file
        let mut file_buf = [0xFFu8; 64];
        let n = rustix::io::pread(&fd, &mut file_buf, 0).expect("pread(2) failed");
        assert_eq!(n, 64);
        assert_eq!(file_buf, [0u8; 64]);
    }

    /// A shared mapping writes through to the underlying file; remapping the
    /// fd read-only afterwards (the only form of protection downgrade the API
    /// supports — there is no mprotect on an existing [MappedSegment]) must
    /// expose the written data
    #[test]
    fn test_shared_mapping_write_through_and_readonly_remap() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let data = b"rosenpass mmap.rs shared-mapping test payload";

        {
            let seg = MapFdConfig::shared_memory()
                .resize_on_mmap(4096)
                .mappable_fd(&fd)
                .mmap()
                .expect("shared RW mapping failed");
            unsafe {
                seg.ptr()
                    .copy_from_nonoverlapping(data.as_ptr(), data.len())
            };
        } // dropped here; writes propagate to the fd since MAP_SHARED

        // Protection downgrade across remaps: read-only mapping of the same fd
        let seg = MapFdConfig::shared_memory()
            .set_immutable()
            .expected_size(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("shared RO remapping failed");
        let mut buf = vec![0u8; data.len()];
        unsafe {
            seg.ptr()
                .copy_to_nonoverlapping(buf.as_mut_ptr(), data.len())
        };
        assert_eq!(&buf[..], &data[..]);
    }

    /// [MappedSegment::unmap] must release the region, reporting success
    #[test]
    fn test_explicit_unmap() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let seg = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("mapping failed");
        seg.unmap().expect("explicit unmap failed");
    }

    /// [MappedSegment::unmap] on a segment whose munmap(2) fails must report
    /// the errno together with the raw parts (so the caller can retry or
    /// free the memory some other way).
    ///
    /// A null pointer with length zero is deterministically rejected by
    /// munmap(2) with EINVAL. Constructing such a deliberately-invalid
    /// handle is what the `unsafe` on [MappedSegment::from_raw_parts] is
    /// for; merely passing it to munmap(2) is a defined, failing syscall.
    #[test]
    fn test_unmap_reports_errno_with_raw_parts() {
        let seg = unsafe { MappedSegment::from_raw_parts(std::ptr::null_mut(), 0) };
        let Err((errno, ptr, len)) = seg.unmap() else {
            panic!("munmap(NULL, 0) must fail");
        };
        assert_eq!(errno, rustix::io::Errno::INVAL);
        assert_eq!(ptr, std::ptr::null_mut());
        assert_eq!(len, 0);
    }

    /// The destructor really calls munmap(2) and panics on failure (the
    /// documented `# Panic` behavior of [MappedSegment]): dropping a
    /// deterministically invalid segment (see
    /// [test_unmap_reports_errno_with_raw_parts]) must panic
    #[test]
    fn test_drop_panics_on_munmap_failure() {
        let res = std::panic::catch_unwind(|| {
            let seg = unsafe { MappedSegment::from_raw_parts(std::ptr::null_mut(), 0) };
            drop(seg);
        });
        assert!(res.is_err(), "drop must panic when munmap(2) fails");
    }

    /// Error path: mmap without a size policy must fail with
    /// [MMapError::MissingSizePolicy]
    #[test]
    fn test_missing_size_policy_rejected() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let res = MapFdConfig::new().mappable_fd(&fd).mmap();
        assert!(matches!(res, Err(MMapError::MissingSizePolicy)));
    }

    /// Error path: the Checked size policy must fail with
    /// [MMapError::IncorrectSize] when the fd's size does not match
    #[test]
    fn test_checked_size_mismatch_rejected() {
        let Some(fd) = test_memfd() else {
            return;
        };

        rustix::fs::ftruncate(&fd, 4096).expect("ftruncate(2) failed");
        let res = MapFdConfig::new()
            .expected_size(8192)
            .mappable_fd(&fd)
            .mmap();
        assert!(
            matches!(
                res,
                Err(MMapError::IncorrectSize {
                    expected: 8192,
                    actual: 4096
                })
            ),
            "expected IncorrectSize, got: {res:?}"
        );
    }

    /// Happy path for resize sealing: mapping a memfd_create(2) file
    /// descriptor with the default configuration seals it against resizing;
    /// F_GET_SEALS must report exactly F_SEAL_SHRINK | F_SEAL_GROW afterwards.
    ///
    /// F_SEAL_SEAL must NOT be set: [MappableFd::mmap] deliberately adds only
    /// the resize-protection seals so the owner can still add further seals
    /// (e.g. F_SEAL_FUTURE_WRITE) afterwards.
    #[test]
    fn test_mmap_seals_memfd_against_resizing() {
        let Some(fd) = test_memfd() else {
            return;
        };

        // A fresh memfd carries no seals
        let seals = fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed");
        assert_eq!(seals, SealFlags::empty());

        let seg = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("mapping failed");
        assert_eq!(seg.len(), 4096);

        let seals = fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed");
        assert!(
            seals.contains(SealFlags::SHRINK) && seals.contains(SealFlags::GROW),
            "missing resize protection seals: {seals:?}"
        );
        assert!(
            !seals.contains(SealFlags::SEAL),
            "mmap must not add F_SEAL_SEAL: {seals:?}"
        );
        assert_eq!(seals, SealFlags::SHRINK | SealFlags::GROW);
    }

    /// The seals added by [MappableFd::mmap] actually take effect: after
    /// mapping, growing and shrinking the file descriptor with ftruncate(2)
    /// both fail with EPERM and its size is unchanged.
    ///
    /// The mapping itself remains fully usable — the pages start out zeroed
    /// and volatile writes/reads through the mapping work — proving that
    /// sealing did not break normal operation of the mapped segment.
    #[test]
    fn test_sealed_memfd_cannot_be_resized_and_stays_usable() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let seg = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("mapping failed");

        // Growing is blocked by F_SEAL_GROW, shrinking by F_SEAL_SHRINK.
        //
        // Note that the kernel rejects the ftruncate(2) calls with EPERM
        // (do_truncate() in fs/open.c), not EINVAL as one might expect
        for size in [8192u64, 2048, 0] {
            let res = rustix::fs::ftruncate(&fd, size);
            assert_eq!(
                res.unwrap_err(),
                Errno::PERM,
                "ftruncate(2) to {size} must fail on the sealed fd"
            );
            assert_eq!(
                Quickstat::new(&fd).size().unwrap(),
                4096,
                "sealed fd must retain its size"
            );
        }

        // The mapping starts zeroed
        let mut buf = [0xFFu8; 64];
        unsafe {
            seg.ptr()
                .copy_to_nonoverlapping(buf.as_mut_ptr(), buf.len())
        };
        assert_eq!(buf, [0u8; 64]);

        // Volatile write + read back through the sealed mapping
        let data = [0x5Au8; 64];
        for (i, b) in data.iter().enumerate() {
            unsafe { seg.ptr().add(i).write_volatile(*b) };
        }
        for (i, b) in data.iter().enumerate() {
            assert_eq!(unsafe { seg.ptr().add(i).read_volatile() }, *b);
        }
    }

    /// Sealing is idempotent: mapping the same file descriptor a second time
    /// (a fresh [MappableFd] on the same fd, using the Checked size policy so
    /// no resize is attempted) must succeed, and the set of seals must still
    /// be exactly F_SEAL_SHRINK | F_SEAL_GROW.
    ///
    /// Re-adding seals that are already present is harmless on Linux as long
    /// as F_SEAL_SEAL is not set; [MappableFd::mmap] relies on this.
    #[test]
    fn test_mmap_sealing_is_idempotent() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let seg1 = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("first mapping failed");
        let seg2 = MapFdConfig::new()
            .expected_size(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("second mapping of the same fd failed");

        assert_eq!(seg1.len(), 4096);
        assert_eq!(seg2.len(), 4096);
        assert_eq!(
            fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed"),
            SealFlags::SHRINK | SealFlags::GROW,
        );

        // Both mappings are usable and independent (MAP_PRIVATE)
        unsafe { seg1.ptr().write_volatile(0xA5) };
        assert_eq!(unsafe { seg1.ptr().read_volatile() }, 0xA5);
        assert_eq!(unsafe { seg2.ptr().read_volatile() }, 0);
    }

    /// A file descriptor that is already sealed against adding further seals
    /// (F_SEAL_SEAL) but lacks the resize-protection seals cannot be secured
    /// by [MappableFd::mmap] anymore; the call must fail with
    /// [MemfdCreateSealError::PresealedWithMissingSeals] and must NOT resize
    /// the file descriptor as a side effect (the early seal check runs before
    /// any ftruncate(2)).
    #[test]
    fn test_mmap_rejects_fd_presealed_against_further_sealing() {
        let Some(fd) = test_memfd() else {
            return;
        };

        // Pre-seal the fd against adding further seals, WITHOUT adding the
        // resize-protection seals first
        fcntl_add_seals(&fd, SealFlags::SEAL).expect("fcntl(F_ADD_SEALS, F_SEAL_SEAL) failed");
        assert_eq!(
            fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed"),
            SealFlags::SEAL,
        );

        let res = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap();
        assert_eq!(
            res.unwrap_err(),
            MMapError::SealError(MemfdCreateSealError::PresealedWithMissingSeals {
                missing: SealFlags::SHRINK | SealFlags::GROW,
            }),
        );

        // The failure must not leave the fd resized as a side effect
        assert_eq!(Quickstat::new(&fd).size().unwrap(), 0);
    }

    /// A memfd_create(2) file descriptor created WITHOUT MFD_ALLOW_SEALING is
    /// born with F_SEAL_SEAL set (see memfd_create(2)), so no seals can ever
    /// be added to it; [MappableFd::mmap] with the default configuration must
    /// reject it with [MemfdCreateSealError::PresealedWithMissingSeals] rather
    /// than map it without resize protection.
    ///
    /// This is why production file descriptors are created with
    /// MFD_ALLOW_SEALING (see
    /// [crate::internal::util::secret_memory::fd::SecretMemfdConfig::create])
    /// and why [MapFdConfig::disable_resizing_protection] exists as an
    /// explicit opt-out for file descriptors that cannot be sealed.
    #[test]
    fn test_mmap_rejects_memfd_created_without_allow_sealing() {
        let fd = match memfd_create(
            "rosenpass mmap.rs unit test (unsealable)",
            MemfdFlags::CLOEXEC,
        ) {
            Ok(fd) => fd,
            Err(Errno::NOSYS | Errno::PERM | Errno::ACCESS) => return,
            Err(e) => panic!("Unexpected error probing memfd_create(2): {e:?}"),
        };

        // Born sealed against adding further seals, with no other seals
        assert_eq!(
            fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed"),
            SealFlags::SEAL,
        );

        let res = MapFdConfig::new()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap();
        assert_eq!(
            res.unwrap_err(),
            MMapError::SealError(MemfdCreateSealError::PresealedWithMissingSeals {
                missing: SealFlags::SHRINK | SealFlags::GROW,
            }),
        );
    }

    /// Opt-out: with [MapFdConfig::disable_resizing_protection],
    /// [MappableFd::mmap] must not touch the seals of the file descriptor at
    /// all: no seals are added and the file descriptor remains freely
    /// resizable after the mapping. The mapping itself is fully usable.
    #[test]
    fn test_mmap_resizing_protection_optout_adds_no_seals() {
        let Some(fd) = test_memfd() else {
            return;
        };

        let seg = MapFdConfig::new()
            .disable_resizing_protection()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("mapping with disabled resizing protection failed");
        assert_eq!(seg.len(), 4096);

        // No seals were added and the fd remains freely resizable
        assert_eq!(
            fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed"),
            SealFlags::empty(),
        );
        rustix::fs::ftruncate(&fd, 8192).expect("fd must remain resizable when protection is off");
        rustix::fs::ftruncate(&fd, 4096).expect("fd must remain resizable when protection is off");

        // The mapping remains usable
        unsafe { seg.ptr().write_volatile(0xA5) };
        assert_eq!(unsafe { seg.ptr().read_volatile() }, 0xA5);
    }

    /// A file descriptor that denies adding seals with EPERM without being
    /// sealed against further seals (a read-only re-open of a memfd through
    /// /proc/self/fd — F_ADD_SEALS requires a writable file descriptor, while
    /// F_GET_SEALS keeps working) can never make sealing progress;
    /// [MappableFd::mmap] must report the persistent permission error
    /// immediately instead of spinning through all retries and misreporting
    /// [MemfdCreateSealError::RetriesAborted].
    #[test]
    fn test_mmap_sealing_persistent_eperm_reported() {
        let Some(fd) = test_memfd() else {
            return;
        };
        rustix::fs::ftruncate(&fd, 4096).expect("ftruncate(2) failed");

        // Read-only view of the same memfd; skip cleanly if procfs is
        // unavailable
        let ro = match std::fs::File::open(format!("/proc/self/fd/{}", fd.as_raw_fd())) {
            Ok(f) => f,
            Err(_) => return,
        };

        let res = MapFdConfig::new()
            .expected_size(4096)
            .mappable_fd(&ro)
            .mmap();
        assert_eq!(
            res.unwrap_err(),
            MMapError::SealError(MemfdCreateSealError::SystemError(Errno::PERM)),
        );
    }

    /// Opt-out on an unsealable file descriptor: a memfd_create(2) file
    /// descriptor created WITHOUT MFD_ALLOW_SEALING is born with F_SEAL_SEAL
    /// (see [test_mmap_rejects_memfd_created_without_allow_sealing]), so the
    /// default configuration rejects it. With
    /// [MapFdConfig::disable_resizing_protection], however, the mapping must
    /// succeed: the seal pre-check and the sealing loop are both skipped
    /// entirely and the fd's seals stay untouched.
    #[test]
    fn test_mmap_unsealable_memfd_with_resizing_protection_optout() {
        let fd = match memfd_create(
            "rosenpass mmap.rs unit test (unsealable, opt-out)",
            MemfdFlags::CLOEXEC,
        ) {
            Ok(fd) => fd,
            Err(Errno::NOSYS | Errno::PERM | Errno::ACCESS) => return,
            Err(e) => panic!("Unexpected error probing memfd_create(2): {e:?}"),
        };

        // Born sealed against adding further seals, with no other seals
        assert_eq!(
            fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed"),
            SealFlags::SEAL,
        );

        let seg = MapFdConfig::new()
            .disable_resizing_protection()
            .resize_on_mmap(4096)
            .mappable_fd(&fd)
            .mmap()
            .expect("mapping an unsealable memfd with disabled resizing protection failed");
        assert_eq!(seg.len(), 4096);

        // The seals are untouched and the fd remains freely resizable
        // (F_SEAL_SEAL itself does not restrict ftruncate(2))
        assert_eq!(
            fcntl_get_seals(&fd).expect("fcntl(F_GET_SEALS) failed"),
            SealFlags::SEAL,
        );
        rustix::fs::ftruncate(&fd, 8192).expect("fd must remain resizable when protection is off");

        // The mapping is usable
        unsafe { seg.ptr().write_volatile(0xA5) };
        assert_eq!(unsafe { seg.ptr().read_volatile() }, 0xA5);
    }

    /// memfd_secret(2) file descriptors are never sealed: secretmem does not
    /// support the fcntl(2) sealing interface, and whether resizing
    /// protection is in effect is a property of the system (see
    /// [crate::internal::util::secret_memory::fd::memfd_secret_support]).
    ///
    /// [crate::internal::util::secret_memory::fd::SecretMemfdConfig::create]
    /// must auto-configure [MapFdConfig::no_resizing_protection] to match the
    /// system property, and [MappableFd::mmap] must succeed without touching
    /// the sealing interface — had any fcntl(2) sealing call been attempted
    /// on the secretmem file descriptor, it would have failed with an error
    /// other than EPERM, aborting the mapping.
    ///
    /// The kernel rejects MAP_PRIVATE mappings of memfd_secret(2) file
    /// descriptors with EINVAL (secretmem_mmap() in mm/secretmem.c), so
    /// [crate::internal::util::secret_memory::fd::SecretMemfdConfig::create]
    /// always sets [MapFdConfig::shared] when memfd_secret(2) is used, even for
    /// non-shared usage; the explicit [MapFdConfig::set_shared] call below is
    /// redundant but harmless.
    ///
    /// The test skips cleanly on systems where memfd_secret(2) is unavailable
    /// (kernel too old, disabled at boot, or blocked by seccomp/LSM policy).
    #[test]
    fn test_mmap_memfd_secret_skips_sealing() {
        use crate::internal::util::secret_memory::fd::{
            SecretMemfdConfig, SecretMemfdPolicy, memfd_secret_protects_against_resizing,
            memfd_secret_support,
        };

        // Skip cleanly when memfd_secret(2) is unavailable on this system
        if memfd_secret_support()
            .expect("probing memfd_secret(2) support failed")
            .is_err()
        {
            return;
        }

        let mfd = SecretMemfdConfig {
            policy: SecretMemfdPolicy::UseMemfdSecret,
            ..SecretMemfdConfig::new()
        }
        .create()
        .expect("memfd_secret(2) failed although support was reported");

        // create() must auto-configure no_resizing_protection consistently
        // with the system's resizing-protection property
        let protects = memfd_secret_protects_against_resizing()
            .expect("probing memfd_secret(2) resizing protection failed");
        assert_eq!(mfd.config().no_resizing_protection, !protects);

        // Mapping must succeed without any sealing; [MappableFd::mmap]
        // rejects a mismatch between the configured and the system-side
        // resizing protection, so this also validates the consistency
        // assertion above end-to-end. MAP_SHARED is required by the kernel
        // for memfd_secret(2) file descriptors.
        let cfg = mfd.config().set_shared().resize_on_mmap(4096);
        let seg = mfd
            .with_config(cfg)
            .mmap()
            .expect("mapping a memfd_secret(2) file descriptor failed");
        assert_eq!(seg.len(), 4096);

        // The mapping is usable
        unsafe { seg.ptr().write_volatile(0xA5) };
        assert_eq!(unsafe { seg.ptr().read_volatile() }, 0xA5);
    }
}
