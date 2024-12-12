//! This module provides a wrapper [MallocAllocator] around the memfdsec allocator in
//! [memsec]. The wrapper implements the [Allocator] trait and thus makes the memfdsec allocator
//! usable as a drop-in replacement wherever the [Allocator] trait is required.
//!
//! The module also provides the [MemfdSecVec] and [MemfdSecBox] types.

#![cfg(target_os = "linux")]
use std::fmt;
use std::ptr::NonNull;

use allocator_api2::alloc::{AllocError, Allocator, Layout};

#[derive(Copy, Clone, Default)]
struct MemfdSecAllocatorContents;

/// A wrapper around the memfdsec allocator in [memsec] that implements the [Allocator] trait from
/// the [allocator_api2] crate.
#[derive(Copy, Clone, Default)]
pub struct MemfdSecAllocator {
    _dummy_private_data: MemfdSecAllocatorContents,
}

/// A [allocator_api2::boxed::Box](allocator_api2::boxed::Box) backed by the memfdsec allocator
/// from the [memsec] crate.
pub type MemfdSecBox<T> = allocator_api2::boxed::Box<T, MemfdSecAllocator>;

/// A [allocator_api2::vec::Vec](allocator_api2::vec::Vec) backed by the memfdsec allocator
/// from the [memsec] crate.
pub type MemfdSecVec<T> = allocator_api2::vec::Vec<T, MemfdSecAllocator>;

/// Try to allocate a [MemfdSecBox] for the type `T`. If `T` is zero-sized the allocation
/// still works. It returns an error if the allocation fails.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::memsec::memfdsec::{memfdsec_box_try, MemfdSecBox};
/// # fn do_test() -> Result<(), Box<dyn std::error::Error>> {
/// let data: u8 = 42;
/// let memfdsec_box: MemfdSecBox<u8> = memfdsec_box_try(data)?;
/// # assert_eq!(*memfdsec_box, 42u8);
/// # Ok(())
/// # }
/// ```
pub fn memfdsec_box_try<T>(x: T) -> Result<MemfdSecBox<T>, AllocError> {
    MemfdSecBox::<T>::try_new_in(x, MemfdSecAllocator::new())
}

/// Allocate a [MemfdSecBox] for the type `T`. If `T` is zero-sized the allocation
/// still works.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::memsec::memfdsec::{memfdsec_box, MemfdSecBox};
/// let data: u8 = 42;
/// let memfdsec_box: MemfdSecBox<u8> = memfdsec_box(data);
/// # assert_eq!(*memfdsec_box, 42u8);
/// ```
pub fn memfdsec_box<T>(x: T) -> MemfdSecBox<T> {
    MemfdSecBox::<T>::new_in(x, MemfdSecAllocator::new())
}

/// Allocate a [MemfdSecVec] for the type `T`. No memory will be actually allocated
/// until elements are pushed to the vector.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::memsec::memfdsec::{memfdsec_vec, MemfdSecVec};
/// let mut memfdsec_vec: MemfdSecVec<u8> = memfdsec_vec();
/// memfdsec_vec.push(0u8);
/// memfdsec_vec.push(1u8);
/// memfdsec_vec.push(2u8);
/// # let mut element = memfdsec_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 2u8);
/// # element = memfdsec_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 1u8);
/// # element = memfdsec_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 0u8);
/// # element = memfdsec_vec.pop();
/// # assert!(element.is_none());
/// ```
pub fn memfdsec_vec<T>() -> MemfdSecVec<T> {
    MemfdSecVec::<T>::new_in(MemfdSecAllocator::new())
}

impl MemfdSecAllocator {
    /// Create a new [MemfdSecAllocator].
    pub fn new() -> Self {
        Self {
            _dummy_private_data: MemfdSecAllocatorContents,
        }
    }
}

unsafe impl Allocator for MemfdSecAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Call memsec allocator
        let mem: Option<NonNull<[u8]>> = unsafe { memsec::memfd_secret_sized(layout.size()) };

        // Unwrap the option
        let Some(mem) = mem else {
            log::error!("Allocation {layout:?} was requested but memfd-based memsec returned a null pointer");
            return Err(AllocError);
        };

        // Ensure the right alignment is used
        let off = (mem.as_ptr() as *const u8).align_offset(layout.align());
        if off != 0 {
            log::error!("Allocation {layout:?} was requested but memfd-based memsec returned allocation \
                with offset {off} from the requested alignment. Memfd always allocates values \
                at the end of a memory page for security reasons, custom alignments are not supported. \
                You could try allocating an oversized value.");
            unsafe { memsec::free_memfd_secret(mem) };
            return Err(AllocError);
        };

        Ok(mem)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            memsec::free_memfd_secret(ptr);
        }
    }
}

impl fmt::Debug for MemfdSecAllocator {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<memsec based Rust allocator>")
    }
}

#[cfg(test)]
mod test {
    use allocator_api2_tests::make_test;

    use super::*;

    make_test! { test_sizes(MemfdSecAllocator::new()) }
    make_test! { test_vec(MemfdSecAllocator::new()) }
    make_test! { test_many_boxes(MemfdSecAllocator::new()) }

    #[test]
    fn memfdsec_allocation() {
        let alloc = MemfdSecAllocator::new();
        memfdsec_allocation_impl::<0>(&alloc);
        memfdsec_allocation_impl::<7>(&alloc);
        memfdsec_allocation_impl::<8>(&alloc);
        memfdsec_allocation_impl::<64>(&alloc);
        memfdsec_allocation_impl::<999>(&alloc);

        // Also test the debug-print for good measure
        let _ = format!("{:?}", alloc);
    }

    fn memfdsec_allocation_impl<const N: usize>(alloc: &MemfdSecAllocator) {
        let layout = Layout::new::<[u8; N]>();
        let mem = alloc.allocate(layout).unwrap();

        // https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations
        // promises us that allocated memory is initialized with the magic byte 0xDB
        // and memsec promises to provide a reimplementation of the libsodium mechanism;
        // it uses the magic value 0xD0 though
        assert_eq!(unsafe { mem.as_ref() }, &[0xD0u8; N]);
        let mem = NonNull::new(mem.as_ptr() as *mut u8).unwrap();
        unsafe { alloc.deallocate(mem, layout) };
    }
}
