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
    pub memfd_config: SecretMemfdConfig,
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
    ///
    /// The
    pub fn allocate(&self) -> Result<OwnedSegment, AllocatorError> {
        self.memfd_config
            .create()?
            .with_config(self.mapping_config)
            .mmap()?
            .apply(|seg| unsafe { OwnedSegment::new(seg) })
            .ok()
    }

    pub fn with_memfd_config(&self, memfd_config: SecretMemfdConfig) -> Self {
        let mut r = self.copy();
        r.memfd_config = memfd_config;
        r
    }

    pub fn with_mapping_config(&self, mapping_config: MappingConfig) -> Self {
        let mut r = self.copy();
        r.mapping_config = mapping_config;
        r
    }

    pub fn sized(&self, size: usize) -> Self {
        let size = U64USize::new_or_panic(size).u64();
        let cfg = self
            .mapping_config
            .set_size_policy(MMapSizePolicy::Resize(size));
        self.with_mapping_config(cfg)
    }

    pub fn enforce_high_security(&self) -> Self {
        let cfg = self.memfd_config.enforce_high_security();
        self.with_memfd_config(cfg)
    }
}

pub struct OwnedSegment {
    inner: MappedSegment,
}

impl OwnedSegment {
    pub unsafe fn new(mapped_segment: MappedSegment) -> Self {
        Self {
            inner: mapped_segment,
        }
    }
}

impl Deref for OwnedSegment {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        unsafe { std::slice::from_raw_parts(self.inner.ptr(), self.inner.len()) }
    }
}

impl DerefMut for OwnedSegment {
    fn deref_mut(&mut self) -> &mut Self::Target {
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
