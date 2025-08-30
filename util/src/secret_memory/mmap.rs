//! This module takes care of allocating memory segments for
//! file descriptors created with [super::fd::memfd_for_secrets_with_default_policy]
//! and anonymous memory segments

// Tests: Nix based integration tests

#![deny(unsafe_op_in_unsafe_fn)]

use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};
use std::ptr::null_mut;

use crate::mem::CopyExt;

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
    /// The memory region can be executed
    pub executable: bool,
    /// The memory region is shared-memory; other mappings of the same
    /// region within and outside this process can see the modifications
    /// to the memory region (as long as they also set the shared flag)
    pub shared: bool,
    /// How [MappableFd::mmap] will determine the size to be used fo
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
            executable: false,
            shared: false,
            size_policy: None,
        }
    }

    /// New MappableFdConfig with shared memory turned on
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

        let p_exec = match self.executable {
            true => P::EXEC,
            false => P::empty(),
        };

        p_read.union(p_write).union(p_exec)
    }

    /// Calculate [rustix::mm::MapFlags] for this configuration
    pub const fn mmap_flags(&self) -> rustix::mm::MapFlags {
        use rustix::mm::MapFlags as M;
        match self.shared {
            true => M::SHARED,
            false => M::empty(),
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
    /// Error converting between usize & f64
    #[error("Requested memory map of size {requested_len} but maximum supported size is {max_supported_len}. \
        This is a low level error that usually arises on architectures where the integer type usize ({} bytes) can not \
        represent all values in u64 ({} bytes). Are you possibly on 32 bit CPU architecture requesting a buffer bigger than 4 GB?\n\
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
    #[error("Tried to map a file descriptor into memory, but the size policy was never set. This is a developer error.")]
    MissingSizePolicy,
    /// fseek(3)/ftell(3) system call failed
    #[error("Tried to map file descriptor into memory, but failed to determine the size of the file descriptor: {:?}", .0)]
    CouldNotDetermineSize(rustix::io::Errno),
    /// Mismatch between expected and actual size of the file descriptor
    #[error("Tried to map file descriptor into memory with expected size {expected:?}, instead we found that the true size is {actual:?}")]
    IncorrectSize {
        /// Expected file descriptor size (given by caller)
        expected: u64,
        /// Actual file descriptor size
        actual: u64,
    },
    /// Negative size reported by fstat(2)
    #[error("Tried to determine the size of the underlying file descriptor, but failed to determine the size of the file descriptor because the size ({size}) is negative: {err:?}")]
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

    /// Determine the size of the data associated with the file descriptor
    pub fn size_of_underlying_data(&self) -> Result<u64, MMapError> {
        use MMapError as E;
        let size = rustix::fs::fstat(self)
            .map_err(E::CouldNotDetermineSize)?
            .st_size;
        size.try_into().map_err(|err| E::InvalidSize { err, size })
    }

    /// Map the file into memory
    ///
    /// # Determining the size of the mapping.
    ///
    /// Before calling this function, [MapFdConfig::size_policy] must be set.
    ///
    /// Note that [Self::from_fd] and [Self::new] still allow you to create a [Self] with
    /// [MapFdConfig::size_policy] set to [None], so you can use [Self::size_of_underlying_data]
    /// to auto-detect the size of the mapping.
    ///
    /// This functionality is not implemented by default, as its crucial to validate the size of
    /// the data being mapped into memory somehow; otherwise, the party that created the file
    /// descriptor can trigger a denial-of-service attack against our process by allocating an
    /// excessively large, sparse file. If you implement size auto-detection facilities, you should
    /// still enforce some bounds on the size.
    ///
    /// # Safety
    ///
    /// If there exist any Rust references referring to the memory region, or if you subsequently create a Rust reference referring to the resulting region, it is your responsibility to ensure that the Rust reference invariants are preserved, including ensuring that the memory is not mutated in a way that a Rust reference would not expect.
    pub fn mmap(&self) -> Result<MappedSegment, MMapError> {
        use rustix::mm::mmap;
        use MMapError as E;

        let prot = self.config().mmap_prot();
        let flags = self.config().mmap_flags();

        // Determine the size of the mapping to be used as u64
        let requested_size = match self.config().size_policy {
            None => return Err(E::MissingSizePolicy),
            Some(MMapSizePolicy::Assumed(size)) => size,
            Some(MMapSizePolicy::Resize(size)) => {
                rustix::fs::ftruncate(self, size).map_err(E::ResizeError)?;
                size
            }
            Some(MMapSizePolicy::Checked(expected)) => {
                let actual = self.size_of_underlying_data()?;
                if expected != actual {
                    return Err(E::IncorrectSize { expected, actual });
                }
                expected
            }
        };

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
/// If the munmap(2) call fails, the destructor will panic. You can avoid this and use explicit
/// error handling by calling [Self::unmap] instead
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
    /// It is the responsibility of the caller to make sure that any pointer P such that `P = ptr.add(n)`,
    /// where `n < len` is a valid pointer. See #safety in [std::ptr].
    pub unsafe fn from_raw_parts(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    /// Decompose a MappedSegment into its raw components: Pointer and length
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
