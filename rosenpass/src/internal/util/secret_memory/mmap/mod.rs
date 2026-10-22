//! This module takes care of allocating memory segments for
//! file descriptors created with [super::fd::SecretMemfdConfig]
//! and anonymous memory segments

#![deny(unsafe_op_in_unsafe_fn)]

use std::ffi::c_void;
use std::mem::ManuallyDrop;
use std::os::fd::AsFd;

use crate::internal::util::mem::CopyExt;

use crate::internal::util::secret_memory::fd::{
    SecretMemfdConfig, SecretMemfdConfigValidationError,
};

mod allocation_code;

/// Size of the memory mapping for [Mappable]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MMapSizePolicy {
    /// Size is checked against this particular value; [Mappable::mmap] will check the
    /// size of the underlying data and raise an error if the size of data and this value
    /// do not match
    Checked(u64),
    /// Size is defined to be this particular value; [Mappable::mmap] will explicitly resize
    /// the underlying file descriptor (if any) to be this particular size when called.
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

/// Configuration for [Mappable::mmap]
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MappingConfig {
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
    /// When using [SecretMemfdConfig::create()], this flag is configured automatically.
    pub shared: bool,
    /// How [Mappable::mmap] will determine the size to be used for the mapping
    ///
    /// You should usually set this value through [Self::set_size_policy],
    /// [Self::expected_size], or [Self::resize_on_mmap].
    pub size_policy: Option<MMapSizePolicy>,
}

impl MappingConfig {
    /// New MappingConfig with all settings turned off
    ///
    /// You still must set [Self::size_policy], otherwise [Mappable::mmap] will raise
    /// an error when called
    pub const fn new() -> Self {
        MappingConfig {
            shared: false,
            size_policy: None,
        }
    }

    /// Alias for [SecretMemfdConfig::map_fd_config()]
    pub fn from_secret_memfd_config(
        cfg: &SecretMemfdConfig,
    ) -> Result<Self, SecretMemfdConfigValidationError> {
        cfg.map_fd_config()
    }

    /// New MappingConfig with shared memory turned on
    pub const fn shared_memory() -> Self {
        Self::new().set_shared()
    }

    /// Set the [Self::shared] flag
    pub const fn set_shared(&self) -> Self {
        let mut r = *self;
        r.shared = true;
        r
    }

    /// Create a [Mappable] instance with this configuration
    pub fn mappable<Fd: AsFd>(&self, fd: Fd) -> Mappable<Fd> {
        Mappable::new(Some(fd), self.copy())
    }

    /// Calculate [rustix::mm::ProtFlags] for this configuration
    pub const fn mmap_prot(&self) -> rustix::mm::ProtFlags {
        use rustix::mm::ProtFlags as P;
        P::READ.union(P::WRITE)
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

/// Errors for [Mappable::mmap()] caused by invalid [MappingConfig] configurations
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MMapInvalidConfigError {
    /// When memory mapping memfd_secret(2) file descriptors, [MappingConfig::shared] MUST be used
    /// as MAP_PRIVATE is not supported by the operating system.
    #[error(
        "\
        When mapping a memfd_secret(2) into memory, MAP_PRIVATE can not be used
        and usage of MAP_SHARED is mandatory. Please always set MappingConfig::shared
        when memory mapping memfd_secret(2) based file descriptors, even if the file
        is not actually shared between processes.\
    "
    )]
    MapSharedNeededForMemfdSecret,
    /// Hugetlbfs-backed file descriptors are not supported: the kernel aligns
    /// the length of a MAP_FIXED mapping up to the hugepage size (see the
    /// mmap(2) NOTES), so replacing the reserved region would consume the
    /// guard pages and overwrite memory beyond the reservation
    #[error(
        "\
        Tried to map a hugetlbfs-backed file descriptor into memory, but hugetlb mappings \
        are not supported: the kernel rounds the length of a MAP_FIXED mapping up to the \
        hugepage size, so the mapping would extend beyond the reserved region and overwrite \
        adjacent memory.\
    "
    )]
    HugetlbNotSupported,
}

/// Errors for sealing memfd_create(2) file descriptors against resizing in [Mappable::mmap()]
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MemfdCreateSealError {
    /// The file descriptor is already sealed against adding further seals while
    /// still missing seals we need to add
    #[error(
        "Tried to seal the underlying file descriptor against being grown/shrunken, but the file descriptor already carried F_SEAL_SEAL, so the seals could not be added."
    )]
    PresealedWithMissingSeals,
    /// The file descriptor was resized while it was being sealed against resizing
    #[error(
        "\
        Tried to seal the underlying file descriptor against being grown/shrunken, but during the process, \
        the file descriptor was resized from the expected size of {} to {}. The file descriptor is now the \
        wrong size, but since it has been sealed, we can no longer resize it.",
        expected,
        actual
    )]
    ResizeRace {
        /// The size the file descriptor was expected to have
        expected: u64,
        /// The size the file descriptor actually had after sealing
        actual: u64,
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

/// Error returned by Mappable::mmap
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MMapError {
    /// Invalid mapping configuration; see [MMapInvalidConfigError]
    #[error("Could not map file descriptor into memory: {0}")]
    InvalidConfig(#[from] MMapInvalidConfigError),
    /// Allocation requested is too big
    #[error("Requested memory map of size {requested_len} but maximum supported size is {max_supported_len}. \
        This is a low level error that arises when the requested size, including guard pages, can not be \
        represented by the platform's usize type ({} bytes wide here; sizes are configured as u64, {} bytes wide). \
        The request exceeds what this platform can address.",
        usize::BITS / 8, u64::BITS / 8
    )]
    OutOfBounds {
        /// The size of the memory map requested
        requested_len: u64,
        /// Maximum supported size
        max_supported_len: u64,
    },
    /// Tried to map a file descriptor into memory, but the size policy was never set. Developer
    /// error.
    #[error(
        "Tried to map memory, but the size policy was never set. This is a developer error."
    )]
    MissingSizePolicy,
    /// Zero-length memory mappings are not supported
    #[error(
        "Tried to map memory with a size of zero; the kernel rejects zero-length mappings with EINVAL"
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
    #[error("Tried to resize the underlying file descriptor, but failed: {}", .0)]
    ResizeError(rustix::io::Errno),
    /// mmap(2) system call failed
    #[error("Tried to map memory, but the mmap(2) system call failed: {}", .0)]
    MapFailed(rustix::io::Errno),
    /// mlock(2) system call failed
    ///
    /// mlock(2) counts against the RLIMIT_MEMLOCK resource limit; see
    /// [Mappable::mmap] for deployment notes
    #[error("Tried to lock the allocated memory region into memory, but the mlock(2) system call failed: {}", .0)]
    MLockError(rustix::io::Errno),
    /// Sealing the file descriptor against resizing failed; see [MemfdCreateSealError]
    #[error(
        "Tried to seal file descriptor against being grown/shrunken before mapping into memory: {0}"
    )]
    SealError(#[from] MemfdCreateSealError),
    /// `madvise(…, MADV_DONTFORK)` failed
    #[error("Tried to protect the allocated memory region against forking using madvise(2) with MADV_DONTFORK, but got following error instead: {}", .0)]
    CouldNotProtectAgainstForks(rustix::io::Errno),
    /// `madvise(…, MADV_DONTDUMP)` failed
    #[error("Tried to protect the allocated memory region against memory dumps using madvise(2) with MADV_DONTDUMP, but got following error instead: {}", .0)]
    CouldNotProtectAgainstMemoryDumps(rustix::io::Errno),
}

/// Handle mapping a file descriptor into memory or creating anonymous memory allocations
pub struct Mappable<Fd> {
    /// The file descriptor this struct refers to
    fd: Option<Fd>,
    /// The configuration for mmap
    config: MappingConfig,
}

impl<Fd: AsFd> Mappable<Fd> {
    /// Create a [Mappable] using the default configuration ([MappingConfig])
    pub fn from_fd(fd: Fd) -> Self {
        Self::new(Some(fd), MappingConfig::default())
    }

    /// Create a new [Mappable] for an existing file descriptor or an anonymous mapping
    ///
    /// Note that while it is sometimes useful to use this function with a file descriptor
    /// obtained through some other means than [SecretMemfdConfig], it generally does not make
    /// sense to use this function manually with None as the file descriptor to create anonymous
    /// mappings. Instead you should go through [SecretMemfdConfig] and set [crate::internal::util::secret_memory::fd::SecretMemfdUsage::allow_anonymous]
    /// through [SecretMemfdConfig::allow_anonymous_mappings()], which will allow you to use a
    /// memfd_secret(2) based mapping on systems where this feature is available or fall back to
    /// an anonymous mapping if this is not supported.
    ///
    /// In most cases, for anonymous mappings, its easiest to use
    /// [crate::internal::util::secret_memory::alloc::SecretMemoryAllocator], which
    /// handles all the steps of creating an anonymous mapping with extra
    /// security features automatically.
    pub fn new(fd: Option<Fd>, config: MappingConfig) -> Self {
        Self { fd, config }
    }

    /// Access the underlying file descriptor
    pub fn fd(&self) -> Option<&Fd> {
        self.fd.as_ref()
    }

    /// Extract the underlying file descriptor
    pub fn into_fd(self) -> Option<Fd> {
        self.fd
    }

    /// Access the [MappingConfig] associated with Self
    pub fn config(&self) -> MappingConfig {
        self.config
    }

    /// Access the [MappingConfig] associated with Self
    pub fn config_mut(&mut self) -> &mut MappingConfig {
        &mut self.config
    }

    /// Modify the [MappingConfig] associated with Self, chainable
    pub fn with_config(mut self, config: MappingConfig) -> Self {
        self.config = config;
        self
    }

    /// Map the file into memory
    ///
    /// # Determining the size of the mapping
    ///
    /// Before calling this function, [MappingConfig::size_policy] must be set.
    ///
    /// Note that [Self::from_fd] and [Self::new] still allow you to create a [Self] with
    /// [MappingConfig::size_policy] set to [None]; the size policy must be configured before
    /// calling this function, otherwise [MMapError::MissingSizePolicy] is raised.
    ///
    /// Auto-detection of the size is deliberately not implemented, as it's crucial to validate
    /// the size of the data being mapped into memory somehow; otherwise, the party that created
    /// the file descriptor can trigger a denial-of-service attack against our process by
    /// allocating an excessively large, sparse file. If you implement size auto-detection
    /// facilities, you should still enforce some bounds on the size.
    ///
    /// # Guard pages
    ///
    /// Guard pages will be allocated before and behind the allocated region.
    /// Note that the allocation size will be rounded up to a multiple of the system page size,
    /// so if the requested size is not a multiple of the page size, there may be some unused
    /// but accessible and valid memory between the end of the allocation and the guard pages.
    ///
    /// # Locking pages into memory
    ///
    /// The mapped pages are locked into memory with mlock(2) unless the file
    /// descriptor is a memfd_secret(2). mlock(2) counts against
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
    /// # Unsupported file descriptors
    ///
    /// Hugetlbfs-backed file descriptors are rejected with
    /// [MMapInvalidConfigError::HugetlbNotSupported]: the kernel rounds the
    /// length of a MAP_FIXED mapping up to the hugepage size, so such a
    /// mapping would extend beyond the reserved region and overwrite adjacent
    /// memory.
    ///
    /// # fork(2)
    ///
    /// The pages allocated here must not be accessed after the process has been forked.
    /// On Linux, MADV_DONTFORK is used so that child processes created by fork(2)
    /// do not inherit these pages as a precaution; this advice is not available on other operating systems.
    ///
    /// # Portability
    ///
    /// Resizing protection through memfd sealing (fcntl(2)) and the
    /// MADV_DONTFORK/MADV_DONTDUMP advice are only available on Linux. On
    /// other operating systems, the mappings created here still perform file
    /// descriptor sizing, guard pages, and mlock(2), but an externally
    /// supplied file descriptor is not protected against hostile resizing by
    /// another party holding it, and the pages are not protected against
    /// being inherited on fork(2) or included in memory dumps.
    pub fn mmap(&self) -> Result<MappedSegment, MMapError> {
        let fd = self.fd.as_ref().map(AsFd::as_fd);
        let me = Mappable::new(fd, self.config());
        allocation_code::AllocationCode::mmap(me)
    }
}

/// Raw data contained in a [MappedSegment]
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct RawMappedSegment {
    /// Pointer to the backing allocation
    pub alloc_ptr: *mut c_void,
    /// Length of the backing allocation in bytes
    pub alloc_len: usize,
    /// The location of the memory segment
    pub ptr: *mut u8,
    /// Length of the segment in bytes
    pub len: usize,
}

impl RawMappedSegment {
    pub fn zero() -> Self {
        Self::default()
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
    inner: RawMappedSegment,
}

unsafe impl Send for MappedSegment {}

impl MappedSegment {
    pub fn raw(&self) -> RawMappedSegment {
        self.inner
    }

    pub fn into_raw(self) -> RawMappedSegment {
        let me = ManuallyDrop::new(self);
        me.raw()
    }

    /// Reconstruct a [MappedSegment] from its raw parts
    ///
    /// # Safety
    ///
    /// `raw` must describe a live mapping owned by this allocator, as produced
    /// by [MappedSegment::into_raw] (the safe producer of such values):
    /// `alloc_ptr`/`alloc_len` must designate the entire guard-paged region
    /// exactly as originally mapped, and `ptr`/`len` the data segment within
    /// it. Ownership of the mapping transfers to the returned
    /// [MappedSegment], which unmaps `alloc_ptr`/`alloc_len` with munmap(2)
    /// on drop (panicking if that fails). The raw value must not be reused,
    /// copied out, or passed to `from_raw` again — doing so would create a
    /// second owner and lead to a double-unmap. Zeroed or null raw values
    /// (e.g. [RawMappedSegment::zero]) are invalid.
    pub unsafe fn from_raw(raw: RawMappedSegment) -> Self {
        Self { inner: raw }
    }

    /// The location of the memory segment
    pub fn ptr(&self) -> *mut u8 {
        self.inner.ptr
    }

    /// Length of the segment in bytes
    #[allow(clippy::len_without_is_empty)]
    pub fn len(&self) -> usize {
        self.inner.len
    }

    /// Release the memory segment
    ///
    /// Compared to using the destructor which panics if unmapping fails, this allows explicit error handling to be used.
    ///
    /// If this returns an error, the memory segment has not been freed and is returned along with
    /// the error.
    pub fn unmap(self) -> Result<(), (rustix::io::Errno, Self)> {
        let me = ManuallyDrop::new(self);
        let res = unsafe { rustix::mm::munmap(me.raw().alloc_ptr.cast(), me.raw().alloc_len) };
        res.map_err(|errno| (errno, ManuallyDrop::into_inner(me)))
    }
}

impl Drop for MappedSegment {
    fn drop(&mut self) {
        let nullseg = MappedSegment {
            inner: RawMappedSegment::zero(),
        };
        let owned = std::mem::replace(self, nullseg);
        if let Err((errno, seg)) = owned.unmap() {
            std::mem::forget(seg);
            panic!("Failed to unmap MappedSegment: {errno:?}")
        }
    }
}
