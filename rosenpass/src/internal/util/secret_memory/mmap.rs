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
use crate::internal::util::secret_memory::fd::memfd_secret_protects_against_resizing;

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
    /// is semantically private; [super::fd::SecretMemfdConfig::create()] therefore always
    /// sets this flag when memfd_secret(2) is used.
    ///
    /// Note that when this flag is used together with [Self::no_resizing_protection],
    /// then the configuration is vulnerable to the attack described in [super::fd::memfd_secret_support()].
    ///
    /// This insecure configuration will not be rejected as it may still be useful in some
    /// scenarios where the other process is trusted.
    ///
    /// When using [super::fd::SecretMemfdConfig::create()], this flag and [Self::no_resizing_protection] are
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
    /// When using [super::fd::SecretMemfdConfig::create()], this flag and [Self::shared] are
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
            return Err(EC::MapSharedNeededForMemfdSecret)?;
        }

        // Validate that the resizing protection settings match the mandatory settings
        // with memfd_secret(2)
        let resize_protection_requested = !self.config.no_resizing_protection;
        if stat.is_memfd_secret()? {
            let resize_protection_enabled =
                memfd_secret_protects_against_resizing().map_err(ES::SystemError)?;
            if resize_protection_requested != resize_protection_enabled {
                return Err(EC::IncorrectResizingProtectionSetting {
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
                return Err(ES::PresealedWithMissingSeals { missing })?;
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
                return Err(ES::RetriesAborted)?;
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
                return Err(ES::PresealedWithMissingSeals { missing })?;
            }

            // Adding seals was denied and the seal set did not change since the
            // last attempt: no progress is possible (e.g. the file descriptor
            // is not writable), so retrying would merely spin until the retry
            // limit; report the persistent permission error instead
            if add_denied && prev_seals == Some(current_seals) {
                return Err(ES::SystemError(Errno::PERM))?;
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
                return Err(ES::ResizeRace {
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
