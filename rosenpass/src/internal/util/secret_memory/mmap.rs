//! This module takes care of allocating memory segments for
//! file descriptors created with [super::fd::memfd_for_secrets_with_default_policy]
//! and anonymous memory segments

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::ptr::null_mut;

use rustix::io::Errno;

use crate::internal::util::mem::CopyExt;

/// Size of the memory mapping for [MappableFd]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum MMapSizePolicy {
    /// Size is assumed to be this particular value; [MappableFd::mmap] will simply
    /// use this value without checking whether its matches the size of the underlying
    /// data
    Assumed(u64),
    /// Size is assumed to be this particular value; [MappableFd::mmap] will check the
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
            Self::Assumed(v) => v,
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
    pub shared: bool,
    /// How [MappableFd::mmap] will determine the size to be used for the mapping
    ///
    /// You should usually set this value through [Self::set_size_policy], [Self::assume_size_without_checking],
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

    /// Set [Self::size_policy] to [MMapSizePolicy::Assumed] with the given value
    pub const fn assume_size_without_checking(&self, size: u64) -> Self {
        self.set_size_policy(MMapSizePolicy::Assumed(size))
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

/// Error returned by MappableFd::mmap
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
pub enum MMapError {
    /// Error converting from u64 to usize
    #[error("Requested memory map of size {requested_len} but maximum supported size is {max_supported_len}. \
        This is a low level error that usually arises on architectures where the integer type usize ({} bytes) can not \
        represent all values in u64 ({} bytes). Are you possibly on a 32-bit CPU architecture requesting a buffer bigger than 4 GB?\n\
          Error: {err:?}",
        (usize::BITS as f64)/8f64, (u64::BITS as f64)/8f64
    )]
    OutOfBounds {
        /// Underlying error
        err: <u64 as TryInto<usize>>::Error,
        /// The size of the memory map requested
        requested_len: u64,
        /// Maximum supported size
        max_supported_len: usize,
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
    /// fseek(3)/ftell(3) system call failed
    #[error("Tried to map file descriptor into memory, but failed to determine the size of the file descriptor: {:?}", .0)]
    CouldNotDetermineSize(rustix::io::Errno),
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

    fn size_of_underlying_data_from_stat(&self) -> Result<u64, MMapError> {
        use MMapError as E;
        let size = rustix::fs::fstat(self)
            .map_err(E::CouldNotDetermineSize)?
            .st_size;
        size.try_into().map_err(|err| E::InvalidSize { err, size })
    }

    /// Determine the size of the data associated with the file descriptor
    fn size_of_underlying_data(&self) -> Result<u64, MMapError> {
        use MMapError as E;
        let size = rustix::fs::fstat(self)
            .map_err(E::CouldNotDetermineSize)?
            .st_size;
        size.try_into().map_err(|err| E::InvalidSize { err, size })
    }

    /// Map the file into memory
    ///
    /// # Determining the size of the mapping
    ///
    /// Before calling this function, [MapFdConfig::size_policy] must be set.
    ///
    /// Note that [Self::from_fd] and [Self::new] still allow you to create a [Self] with
    /// [MapFdConfig::size_policy] set to [None], so you can use [Self::size_of_underlying_data]
    /// to auto-detect the size of the mapping.
    ///
    /// This functionality is not implemented by default, as it's crucial to validate the size of
    /// the data being mapped into memory somehow; otherwise, the party that created the file
    /// descriptor can trigger a denial-of-service attack against our process by allocating an
    /// excessively large, sparse file. If you implement size auto-detection facilities, you should
    /// still enforce some bounds on the size.
    ///
    /// # Safety
    ///
    /// If there exist any Rust references referring to the memory region, or if you subsequently create a Rust reference referring to the resulting region, it is your responsibility to ensure that the Rust reference invariants are preserved, including ensuring that the memory is not mutated in a way that a Rust reference would not expect.
    pub fn mmap(&self) -> Result<MappedSegment, MMapError> {
        use MMapError as E;
        use rustix::mm::mmap;

        let prot = self.config().mmap_prot();
        let flags = self.config().mmap_flags();

        // Determine the size of the mapping to be used as u64
        let (requested_size, actual_size) = match self.config().size_policy {
            None => return Err(E::MissingSizePolicy),
            Some(MMapSizePolicy::Assumed(size)) => (size, size),
            Some(MMapSizePolicy::Resize(size)) => (size, self.size_of_underlying_data()?),
            Some(MMapSizePolicy::Checked(expected)) => {
                let actual = self.size_of_underlying_data()?;
                if expected != actual {
                    return Err(E::IncorrectSize { expected, actual });
                }
                (expected, actual)
            }
        };

        // The kernel rejects zero-length mappings with EINVAL; reject them
        // up front, BEFORE any ftruncate(2) below, so a failed mmap never
        // leaves the underlying file descriptor truncated as a side effect
        if requested_size == 0 {
            return Err(E::ZeroSize);
        }

        // Resize the file descriptor if requested and necessary
        if let Some(MMapSizePolicy::Resize(size)) = self.config().size_policy {
            if requested_size != actual_size {
                rustix::fs::ftruncate(self, size).map_err(E::ResizeError)?;
            }
        }

        // Cast the size of the mapping to be used to usize, raising an error if the
        // requested_size can not be represented as usize (this should never happen in general,
        // but it could conceivably be thrown on 32 bit systems when very large mappings (>= 4GB)
        // are requested
        let len = requested_size.try_into().map_err(|err| {
            let max_supported_len = usize::MAX;
            E::OutOfBounds {
                err,
                requested_len: requested_size,
                max_supported_len,
            }
        })?;

        let ptr = unsafe { mmap(null_mut(), len, prot, flags, self, 0) };
        let ptr = ptr.map_err(E::MMapError)?;
        let ptr = unsafe { MappedSegment::from_raw_parts(ptr.cast(), len) };

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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::os::fd::OwnedFd;

    use rustix::fs::MemfdFlags;
    use rustix::io::Errno;

    use super::*;
    use crate::internal::util::rustix::memfd_create;

    /// Create a memfd for testing via the crate's own memfd helpers
    ///
    /// Returns [None] — skipping the test gracefully — if memfd_create(2) is
    /// unavailable on this system (ENOSYS: kernel too old; EPERM/EACCES:
    /// blocked by seccomp/LSM policy)
    fn test_memfd() -> Option<OwnedFd> {
        match memfd_create("rosenpass mmap.rs unit test", MemfdFlags::CLOEXEC) {
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
        let size_of = || {
            MapFdConfig::new()
                .mappable_fd(&fd)
                .size_of_underlying_data()
                .unwrap()
        };
        assert_eq!(size_of(), 4096);

        for cfg in [
            MapFdConfig::new().resize_on_mmap(0),
            MapFdConfig::new().assume_size_without_checking(0),
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
}
