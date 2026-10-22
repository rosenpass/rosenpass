//! Memory allocation facilities for secret memory

use std::{
    alloc::{AllocError, Allocator},
    convert::Infallible,
    ffi::c_void,
    mem::{ManuallyDrop, MaybeUninit},
    num::NonZero,
};

use rustix::param::page_size;
use zeroize::Zeroize;

use crate::internal::util::{
    functional::ApplyExt,
    mem::CopyExt,
    result::{GuaranteedValue, OkExt},
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
/// Allocation contents are wiped before unmapping, including storage released
/// during reallocation.
///
/// Zero-sized layouts return an aligned dangling pointer without creating a
/// mapping or guard pages; their deallocation is a no-op. Layouts with
/// alignments larger than the system page size are unsupported and return [AllocError].
/// Unexpected panics during allocation or deallocation abort the process by design;
/// ordinary allocation failures return [AllocError].
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

#[derive(thiserror::Error, Debug)]
#[error("Sentinel value mismatch at address {addr:?}!\n
    Upon allocation, when the data allocated is not a multiple of the page size, \
    the secret memory allocator adds a sentinel value to the back of the page. When this \
    sentinel value changes, somebody must have been illegally writing to that unused bit of \
    memory. This can happen when:\n\
    \n\
    1. There was a buffer overflow (or other forbidden/unsound memory access) somewhere in the application; likely in the code that used the allocation.\n\
    2. An attacker managed to achieve remote code execution and is now writing into memory at places where it should not write.\n\
    3. There is a bug in the memory allocator code.")]
struct SentinelMismatch {
    pub addr: *const u8,
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
        let mut me = mappable
            .with_config(config)
            .mmap()
            .map_err(log_alloc_err)?
            .apply(Self::from_mapped_segment);

        me.validate_allocation_layout(layout);
        me.write_sentinel();

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
        assert!(self.sentinel_len() < page_size());
    }

    fn write_sentinel(&mut self) {
        let sentinel = self.sentinel_as_bytes();
        generate_sentinel::<Infallible, _>(sentinel.len(), |off, src| {
            let (start, end) = (off, off + src.len());
            let dest = &mut sentinel[start..end];
            dest.write_copy_of_slice(src);
            Ok(())
        })
        .guaranteed()
    }

    unsafe fn validate_sentinel(&mut self) -> Result<(), SentinelMismatch> {
        let sentinel: &[u8] = unsafe { self.sentinel_as_init_bytes() };
        generate_sentinel(sentinel.len(), |off, expected| {
            let (start, end) = (off, off + expected.len());
            let actual = &sentinel[start..end];
            let mismatch = actual
                .iter()
                .zip(expected.iter())
                .position(|(a, b)| a != b)
                .map(|pos| (&actual[pos..]).as_ptr());

            match mismatch {
                Some(addr) => Err(SentinelMismatch { addr }),
                None => Ok(()),
            }
        })
    }

    fn data_as_bytes(&mut self) -> &mut [MaybeUninit<u8>] {
        use std::slice::from_raw_parts_mut;
        unsafe { from_raw_parts_mut(self.data_ptr().as_ptr().cast(), self.data_len()) }
    }

    fn sentinel_as_bytes(&mut self) -> &mut [MaybeUninit<u8>] {
        use std::slice::from_raw_parts_mut;
        unsafe { from_raw_parts_mut(self.sentinel_ptr().as_ptr().cast(), self.sentinel_len()) }
    }

    unsafe fn sentinel_as_init_bytes(&mut self) -> &mut [u8] {
        unsafe { self.sentinel_as_bytes().assume_init_mut() }
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

    fn sentinel_ptr(&self) -> std::ptr::NonNull<[u8]> {
        let addr = NonZero::new(self.sentinel_start()).unwrap();
        self.data_ptr().with_addr(addr)
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

    #[allow(unused)]
    fn data_pages_start(&self) -> usize {
        self.data_ptr().addr().get()
    }

    fn sentinel_start(&self) -> usize {
        self.data_end()
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

    fn sentinel_end(&self) -> usize {
        self.data_pages_end()
    }

    fn front_guard_len(&self) -> usize {
        self.data_start() - self.alloc_start()
    }

    fn back_guard_len(&self) -> usize {
        self.alloc_end() - self.data_pages_end()
    }

    fn sentinel_len(&self) -> usize {
        self.sentinel_end() - self.sentinel_start()
    }
}

impl Drop for AllocatorSegment {
    fn drop(&mut self) {
        self.data_as_bytes().zeroize();
        unsafe { self.validate_sentinel() }
            .expect("Secret memory sentinel validation failed during deallocation");
    }
}

fn log_alloc_err<E: std::fmt::Display>(e: E) -> std::alloc::AllocError {
    log::warn!("Could not allocate secret memory: {e}");
    std::alloc::AllocError
}

#[derive(thiserror::Error)]
enum SentinelInternalError<E> {
    EndOfFile,
    Other(E),
}

fn generate_sentinel<Err, F: FnMut(usize, &[u8]) -> Result<(), Err>>(
    len: usize,
    handler: F,
) -> Result<(), Err> {
    SentinelGenerator::generate_sentinel(len, handler)
}

struct SentinelGenerator<Err, F: FnMut(usize, &[u8]) -> Result<(), Err>> {
    off: usize,
    len: usize,
    tail_reservation: usize,
    handler: F,
}

impl<Err, F: FnMut(usize, &[u8]) -> Result<(), Err>> SentinelGenerator<Err, F> {
    fn generate_sentinel(len: usize, handler: F) -> Result<(), Err> {
        use SentinelInternalError as E;
        match Self::new(len, handler).generate_sentinel_impl() {
            Ok(()) | Err(E::EndOfFile) => Ok(()),
            Err(E::Other(e)) => Err(e),
        }
    }

    fn new(len: usize, handler: F) -> Self {
        let (off, tail_reservation) = (0, 0);
        Self {
            off,
            len,
            tail_reservation,
            handler,
        }
    }

    fn generate_sentinel_impl(&mut self) -> Result<(), SentinelInternalError<Err>> {
        use SentinelInternalError as E;

        self.tail_reservation = 1; // Reserve space for the final zero char
        match self.generate_penultimate_sentinel() {
            Ok(()) | Err(E::EndOfFile) => {}
            Err(e) => Err(e)?,
        }

        // Write final zero character
        self.tail_reservation = 0;
        self.write(b"\x00")?;

        Ok(())
    }

    fn generate_penultimate_sentinel(&mut self) -> Result<(), SentinelInternalError<Err>> {
        #[rustfmt::skip]
        const TEMPLATES: [&[u8]; 3] = [
            b"SECRET MEMORY SENTINEL",
            b"MEMORY SENTINEL",
            b"SENTINEL"
        ];
        #[rustfmt::skip]
        const SEP0_TEMPLATES: [&[u8]; 4] = [
            b"\x07|- ", // All initial separators start with the BEL character
            b"\x07| ",
            b"\x07|",
            b"\x07",
        ];
        const SEP: &[u8] = b" -|- ";

        // Find the first template that actually fits entirely into the free space
        // we have to work with; if none fits, the shortest (last) template is used
        let template = TEMPLATES
            .iter()
            .copied()
            .find(|t| t.len() >= self.free_space())
            .or(TEMPLATES.last().copied())
            .unwrap();

        // Find the first beginning separator that, together with the template above,
        // actually fits entirely into the free space we have to work with; if none fits,
        // the shortest (last) template is used
        let sep0 = SEP0_TEMPLATES
            .iter()
            .copied()
            .find(|t| t.len() >= self.free_space())
            .or(SEP0_TEMPLATES.last().copied())
            .unwrap();

        // Write the initial separator
        self.write(sep0)?;

        // Write template & separator until EOF
        loop {
            self.write(template)?;
            self.write(SEP)?;
        }
    }

    fn write(&mut self, slice: &[u8]) -> Result<(), SentinelInternalError<Err>> {
        use SentinelInternalError as E;

        let src = {
            let to_write = std::cmp::min(self.free_space(), slice.len());
            &slice[0..to_write]
        };

        // Elide zero-length calls
        if !src.is_empty() {
            let handler = &mut self.handler;
            match handler(self.off, src) {
                Err(e) => Err(E::Other(e))?,
                Ok(()) => {} // pass
            }
        }

        self.off += src.len();

        match self.free_space() > 0 {
            true => Ok(()),
            false => Err(E::EndOfFile),
        }
    }

    fn free_space(&self) -> usize {
        self.len
            .checked_sub(self.off)
            .unwrap()
            .saturating_sub(self.tail_reservation)
    }
}
