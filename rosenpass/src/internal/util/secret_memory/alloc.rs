//! Memory allocation facilities for secret memory

use std::{
    alloc::{AllocError, Allocator},
    ffi::c_void,
    mem::ManuallyDrop,
};

use rustix::param::page_size;

use crate::internal::util::{
    functional::ApplyExt,
    mem::CopyExt,
    result::OkExt,
    secret_memory::{
        fd::{SecretMemfdConfig, SecretMemfdConfigValidationError},
        mmap::{MappedSegment, RawMappedSegment},
    },
};

/// A configurable memory allocator for secret memory regions
///
/// The allocation proceeds in roughly two phases:
///
/// 1. Creating a [crate::internal::util::secret_memory::mmap::Mappable] using
///    [SecretMemfdConfig::create()] in [SecretMemoryAllocator::new()]
/// 2. Allocating this into memory using
///    [crate::internal::util::secret_memory::mmap::Mappable::mmap()]
///
/// Zero-sized layouts return an aligned dangling pointer without creating a
/// mapping or guard pages; their deallocation is a no-op. Layouts with
/// alignments larger than the system page size are unsupported and return [AllocError].
/// Unexpected panics during allocation or deallocation abort the process, as
/// required by the [Allocator] contract; ordinary allocation failures return [AllocError].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SecretMemoryAllocator {
    /// Secret memory governance mechanism. This is used to set up the
    /// file descriptor backing the memory allocation. Based on policy,
    /// different mechanisms such as memfd_secret(2), memfd_create(2), or
    /// anonymous allocations (no file descriptor) are used
    pub memfd_config: SecretMemfdConfig,
}

impl Default for SecretMemoryAllocator {
    fn default() -> Self {
        Self {
            memfd_config: SecretMemfdConfig::new().allow_anonymous_mappings(),
        }
    }
}

impl SecretMemoryAllocator {
    /// Create a new configuration for later allocations
    ///
    /// The [Self::memfd_config] is created using [SecretMemfdConfig::new()]
    /// with anonymous mappings enabled ([SecretMemfdConfig::allow_anonymous_mappings()]).
    /// This is equivalent to [Self::default()].
    pub fn new() -> Result<Self, SecretMemfdConfigValidationError> {
        Ok(Self::default())
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

unsafe impl Allocator for SecretMemoryAllocator {
    fn allocate(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, std::alloc::AllocError> {
        std::panic::catch_unwind(|| {
            AllocatorSegment::allocate(self, layout)?
                .into_alloc_ptr()
                .ok()
        })
        .unwrap_or_else(|_| std::process::abort())
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) {
        std::panic::catch_unwind(|| {
            std::mem::drop(AllocatorSegment::from_alloc_ptr_and_layout(ptr, layout))
        })
        .unwrap_or_else(|_| std::process::abort())
    }
}

#[derive(Debug)]
enum AllocatorSegment {
    Mapped(MappedSegment),
    ZeroSized(std::ptr::NonNull<u8>),
}

impl AllocatorSegment {
    pub fn allocate(
        alloc: &SecretMemoryAllocator,
        layout: std::alloc::Layout,
    ) -> Result<Self, AllocError> {
        if layout.align() > page_size() {
            return Err(AllocError);
        } else if layout.size() == 0 {
            return Ok(Self::ZeroSized(layout.dangling_ptr()));
        }

        let mappable = alloc.memfd_config.create().map_err(log_alloc_err)?;
        let config = mappable.config().resize_on_mmap(layout.size() as u64);
        let me = mappable
            .with_config(config)
            .mmap()
            .map_err(log_alloc_err)?
            .apply(Self::from_mapped_segment);

        me.validate_allocation_layout(layout);

        Ok(me)
    }

    fn from_mapped_segment(mapped_segment: MappedSegment) -> Self {
        let me = Self::Mapped(mapped_segment);
        me.validate_memory_layout();
        me
    }

    fn from_alloc_ptr_and_layout(ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) -> Self {
        if layout.size() == 0 {
            return Self::ZeroSized(ptr);
        }

        let (ptr, len) = (ptr.as_ptr(), layout.size());
        let data_pages_len = len.next_multiple_of(page_size());
        let alloc_ptr = ptr.wrapping_sub(page_size()).cast();
        let alloc_len = data_pages_len + 2 * page_size();

        let seg = RawMappedSegment {
            alloc_ptr,
            alloc_len,
            ptr,
            len,
        };
        let seg = unsafe { MappedSegment::from_raw(seg) };
        let seg = Self::from_mapped_segment(seg);

        seg.validate_allocation_layout(layout);

        seg
    }

    fn into_alloc_ptr(self) -> std::ptr::NonNull<[u8]> {
        let me = ManuallyDrop::new(self);
        me.data_ptr()
    }

    fn validate_allocation_layout(&self, layout: std::alloc::Layout) {
        assert!(matches!(self, Self::Mapped(_)) && self.data_start().is_multiple_of(page_size()));
        assert_eq!(self.data_len(), layout.size());
        assert!(self.data_start().is_multiple_of(layout.align()));
    }

    fn validate_memory_layout(&self) {
        let guard_len = match self {
            Self::Mapped(_) => page_size(),
            Self::ZeroSized(_) => 0,
        };
        assert_eq!(self.front_guard_len(), guard_len);
        assert_eq!(self.back_guard_len(), guard_len);
        assert!(self.unused_len() < page_size());
    }

    fn alloc_ptr(&self) -> std::ptr::NonNull<*mut c_void> {
        match self {
            Self::Mapped(inner) => std::ptr::NonNull::new(inner.raw().alloc_ptr)
                .unwrap()
                .cast(),
            Self::ZeroSized(ptr) => ptr.cast(),
        }
    }

    fn data_ptr(&self) -> std::ptr::NonNull<[u8]> {
        let ptr = match self {
            Self::Mapped(inner) => inner.raw().ptr.apply(std::ptr::NonNull::new).unwrap(),
            Self::ZeroSized(ptr) => ptr.copy(),
        };

        std::ptr::NonNull::slice_from_raw_parts(ptr, self.data_len())
    }

    fn alloc_len(&self) -> usize {
        match self {
            Self::Mapped(inner) => inner.raw().alloc_len,
            Self::ZeroSized(_) => 0,
        }
    }

    fn data_len(&self) -> usize {
        match self {
            Self::Mapped(inner) => inner.raw().len,
            Self::ZeroSized(_) => 0,
        }
    }

    fn data_pages_len(&self) -> usize {
        self.data_len().next_multiple_of(page_size())
    }

    fn alloc_start(&self) -> usize {
        self.alloc_ptr().addr().get()
    }

    fn data_start(&self) -> usize {
        self.data_ptr().addr().get()
    }

    fn data_pages_start(&self) -> usize {
        self.data_ptr().addr().get()
    }

    fn data_end(&self) -> usize {
        self.data_start().wrapping_add(self.data_len())
    }

    fn alloc_end(&self) -> usize {
        self.alloc_start().wrapping_add(self.alloc_len())
    }

    fn data_pages_end(&self) -> usize {
        self.data_start().wrapping_add(self.data_pages_len())
    }

    fn front_guard_len(&self) -> usize {
        self.data_start() - self.alloc_start()
    }

    fn back_guard_len(&self) -> usize {
        self.alloc_end() - self.data_pages_end()
    }

    fn unused_len(&self) -> usize {
        self.data_pages_end() - self.data_end()
    }
}

fn log_alloc_err<E: std::fmt::Display>(e: E) -> std::alloc::AllocError {
    log::warn!("Could not allocate secret memory: {e}");
    std::alloc::AllocError
}
