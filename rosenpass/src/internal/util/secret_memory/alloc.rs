//! Memory allocation facilities for secret memory

use std::{
    borrow::{Borrow, BorrowMut},
    ops::{Deref, DerefMut},
};

use crate::internal::util::{
    functional::ApplyExt,
    int::u64uint::U64USize,
    mem::CopyExt,
    result::OkExt,
    secret_memory::{
        fd::{SecretMemfdConfig, SecretMemfdConfigValidationError, SecretMemfdWithConfigError},
        mmap::{MMapError, MMapSizePolicy, MappedSegment, MappingConfig},
    },
};

/// Allocate a segment of memory in a particularly secure way
/// and expose the resulting memory segment as an [OwnedSegment]
///
/// This is just a shorthand for:
///
/// 1. Creating an [AllocatorConfig] using [AllocatorConfig::new()]
/// 2. Installing a size configuration using [AllocatorConfig::sized()]
/// 3. Calling [AllocatorConfig::allocate()]
///
/// The [SecretMemfdConfigValidationError] from [AllocatorConfig::new()] is
/// exposed as a [SecretMemfdWithConfigError::InvalidConfig] error.
pub fn allocate(size: usize) -> Result<OwnedSegment, AllocatorError> {
    AllocatorConfig::new()
        .map_err(SecretMemfdWithConfigError::InvalidConfig)?
        .sized(size)
        .allocate()
}

/// Errors during allocation of secret memory
#[derive(Copy, Clone, PartialEq, Eq, Debug, thiserror::Error)]
pub enum AllocatorError {
    /// Error creating the [crate::internal::util::secret_memory::mmap::Mappable] using [SecretMemfdConfig::create()]
    #[error("Could not create the secret memory file descriptor or set up the anonymous mapping: {}", .0)]
    MemfdError(#[from] SecretMemfdWithConfigError),
    /// Error while trying to map the memory file descriptor/the anonymous segment into memory
    /// using [crate::internal::util::secret_memory::mmap::Mappable::mmap()]
    #[error("Could not allocate secret memory: {}", .0)]
    MMapError(#[from] MMapError),
}

/// A configurable memory allocator for secret memory regions
///
/// The allocation proceeds in roughly two phases:
///
/// 1. Creating a [crate::internal::util::secret_memory::mmap::Mappable] using
///    [SecretMemfdConfig::create()] in [AllocatorConfig::new()]
/// 2. Allocating this into memory using
///    [crate::internal::util::secret_memory::mmap::Mappable::mmap()]
/// 3. Wrapping the resulting [MappedSegment] into an [OwnedSegment] for convenient access
#[derive(Default, Copy, Clone, PartialEq, Eq, Debug)]
pub struct AllocatorConfig {
    /// Secret memory governance mechanism. This is used to set up the
    /// file descriptor backing the memory allocation. Based on policy,
    /// different mechanisms such as memfd_secret(2), memfd_create(2), or
    /// anonymous allocations (no file descriptor) are used
    pub memfd_config: SecretMemfdConfig,
    /// Settings for the memory allocation itself
    pub mapping_config: MappingConfig,
}

impl AllocatorConfig {
    /// Create a new configuration for later allocations
    ///
    /// The [Self::memfd_config] is created using [SecretMemfdConfig::new()]
    /// with anonymous mappings enabled ([SecretMemfdConfig::allow_anonymous_mappings()])
    /// and the [Self::mapping_config] is derived using [SecretMemfdConfig::map_fd_config()].
    pub fn new() -> Result<Self, SecretMemfdConfigValidationError> {
        let memfd_config = SecretMemfdConfig::new().allow_anonymous_mappings();
        let mapping_config = memfd_config.map_fd_config()?;
        Ok(Self {
            memfd_config,
            mapping_config,
        })
    }

    /// Allocate a segment of memory with this allocator configuration
    ///
    /// This is pretty much just a convenience wrapper for:
    ///
    /// 1. Creating a secret memory [crate::internal::util::secret_memory::mmap::Mappable] (i.e. a
    ///    memfd(2)/memfd_secret(2) file descriptor or no file descriptor for an anonymous mapping)
    /// 2. Applying the config from [AllocatorConfig::mapping_config] via [crate::internal::util::secret_memory::mmap::Mappable::with_config()]
    /// 3. Mapping the [crate::internal::util::secret_memory::mmap::Mappable] into memory using [crate::internal::util::secret_memory::mmap::Mappable::mmap()]
    /// 4. Wrapping the [crate::internal::util::secret_memory::mmap::MappedSegment] in [OwnedSegment] so the allocated memory can actually be accessed
    pub fn allocate(&self) -> Result<OwnedSegment, AllocatorError> {
        self.memfd_config
            .create()?
            .with_config(self.mapping_config)
            .mmap()?
            .apply(|seg| unsafe { OwnedSegment::new(seg) })
            .ok()
    }

    /// Return a copy with an updated [SecretMemfdConfig]
    ///
    /// Note that this does not update [Self::mapping_config],
    /// with the value from [SecretMemfdConfig::map_fd_config()].
    /// If this behavior is desired, you must update [Self::mapping_config]
    /// yourself.
    pub fn with_memfd_config(&self, memfd_config: SecretMemfdConfig) -> Self {
        let mut r = self.copy();
        r.memfd_config = memfd_config;
        r
    }

    /// Return a copy with an updated [MappingConfig]
    pub fn with_mapping_config(&self, mapping_config: MappingConfig) -> Self {
        let mut r = self.copy();
        r.mapping_config = mapping_config;
        r
    }

    /// Return a copy requesting `size` data bytes via via the [MMapSizePolicy::Resize] policy
    pub fn sized(&self, size: usize) -> Self {
        let size = U64USize::new_or_panic(size).u64();
        let cfg = self
            .mapping_config
            .set_size_policy(MMapSizePolicy::Resize(size));
        self.with_mapping_config(cfg)
    }

    /// Return a copy requiring memfd_secret(2) backed allocations even on systems
    /// where this is not supported.
    ///
    /// Delegates to [SecretMemfdConfig::enforce_high_security()].
    ///
    /// If this is set and memfd_secret(2) based allocations are not enabled on the system,
    /// then [Self::allocate()] will return an error instead of falling back to less secure
    /// configurations.
    pub fn enforce_high_security(&self) -> Self {
        let cfg = self.memfd_config.enforce_high_security();
        self.with_memfd_config(cfg)
    }
}

/// An exclusively owned mapped data segment accessible as a byte slice.
pub struct OwnedSegment {
    /// Owns the backing allocation and identifies the data range satisfying
    /// [OwnedSegment::new()]'s slice-access and lifetime requirements.
    inner: MappedSegment,
}

impl OwnedSegment {
    /// Take ownership of a mapping and enable safe shared and mutable byte-slice access.
    ///
    /// This does not validate the mapping's protection, length, or aliasing, and
    /// does not initialize its contents or change its protection.
    ///
    /// # Safety
    ///
    /// The caller must establish and maintain the following until this value is
    /// dropped, including for the full lifetime of every slice borrowed from it:
    ///
    /// - `mapped_segment.ptr()` must be live, non-null, properly aligned for `u8`,
    ///   and carry provenance permitting access to the data range, even at zero length.
    /// - The entire `mapped_segment.len()`-byte data range must be initialized,
    ///   readable, and writable, and lie within a single allocation. Its length
    ///   must not exceed `isize::MAX`, and computing its end must not wrap the
    ///   address space. Guard pages must be outside this range.
    /// - Access to the data must be exclusive to this owner and its borrows. There
    ///   must be no outstanding references at construction and no conflicting
    ///   access through retained pointers, aliased mappings, or another thread or
    ///   process. This includes mutation through a backing-file descriptor: bytes
    ///   must not change behind a shared slice, and a mutable slice must have
    ///   exclusive access, including against reads through such aliases.
    /// - The data range must remain valid and readable+writable: no truncation,
    ///   unmapping, remapping, protection change (mprotect), or fork may invalidate
    ///   it or introduce conflicting aliases. In particular, a forked child must
    ///   not access or drop an inherited value whose mapping was excluded by
    ///   MADV_DONTFORK.
    /// - `mapped_segment` must exclusively own its complete live backing
    ///   allocation, including any guards, with a page-aligned base, valid length,
    ///   and provenance suitable for its eventual munmap in [MappedSegment]'s
    ///   destructor. At destruction its page-rounded range must be valid to mutate
    ///   with that provenance and contain no live Rust references. No other owner
    ///   may release or replace that allocation.
    pub unsafe fn new(mapped_segment: MappedSegment) -> Self {
        Self {
            inner: mapped_segment,
        }
    }
}

impl Deref for OwnedSegment {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        // SAFETY: OwnedSegment::new requires a live, non-null, aligned pointer
        // to initialized readable data in one allocation, with len <= isize::MAX
        // and no address-space wrap. Ownership keeps it valid for this borrow,
        // and the constructor contract excludes mutation behind the shared slice.
        unsafe { std::slice::from_raw_parts(self.inner.ptr(), self.inner.len()) }
    }
}

impl DerefMut for OwnedSegment {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: OwnedSegment::new requires initialized readable+writable data
        // in one live allocation with a non-null aligned pointer, len <= isize::MAX,
        // and no address-space wrap. Its no-alias contract and this exclusive
        // borrow ensure no other access occurs while the mutable slice is live.
        unsafe { std::slice::from_raw_parts_mut(self.inner.ptr(), self.inner.len()) }
    }
}

impl Borrow<[u8]> for OwnedSegment {
    fn borrow(&self) -> &[u8] {
        self.deref()
    }
}

impl BorrowMut<[u8]> for OwnedSegment {
    fn borrow_mut(&mut self) -> &mut [u8] {
        self.deref_mut()
    }
}
