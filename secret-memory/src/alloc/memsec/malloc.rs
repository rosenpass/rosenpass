//! This module provides a wrapper [MallocAllocator] around the memsec allocator in
//! [memsec]. The wrapper implements the [Allocator] trait and thus makes the memsec allocator
//! usable as a drop-in replacement wherever the [Allocator] trait is required.
//!
//! The module also provides the [MallocVec] and [MallocBox] types.

use std::fmt;
use std::ptr::NonNull;

use allocator_api2::alloc::{AllocError, Allocator, Layout};

#[derive(Copy, Clone, Default)]
struct MallocAllocatorContents;

/// A wrapper around the memsec allocator in [memsec] that implements the [Allocator] trait from
/// the [allocator_api2] crate.
#[derive(Copy, Clone, Default)]
pub struct MallocAllocator {
    _dummy_private_data: MallocAllocatorContents,
}

/// A [allocator_api2::boxed::Box] backed by the memsec allocator
/// from the [memsec] crate.
pub type MallocBox<T> = allocator_api2::boxed::Box<T, MallocAllocator>;

/// A [allocator_api2::vec::Vec] backed by the memsec allocator
/// from the [memsec] crate.
pub type MallocVec<T> = allocator_api2::vec::Vec<T, MallocAllocator>;

/// Try to allocate a [MallocBox] for the type `T`. If `T` is zero-sized the allocation
/// still works. It returns an error if the allocation fails.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::memsec::malloc::{malloc_box_try, MallocBox};
/// # fn do_test() -> Result<(), Box<dyn std::error::Error>> {
/// let data: u8 = 42;
/// let malloc_box: MallocBox<u8> = malloc_box_try(data)?;
/// # assert_eq!(*malloc_box, 42u8);
/// # Ok(())
/// # }
/// # let _ = do_test();
/// ```
pub fn malloc_box_try<T>(x: T) -> Result<MallocBox<T>, AllocError> {
    MallocBox::<T>::try_new_in(x, MallocAllocator::new())
}

/// Allocate a [MallocBox] for the type `T`. If `T` is zero-sized the allocation
/// still works.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::memsec::malloc::{malloc_box, MallocBox};
/// let data: u8 = 42;
/// let malloc_box: MallocBox<u8> = malloc_box(data);
/// # assert_eq!(*malloc_box, 42u8);
/// ```
pub fn malloc_box<T>(x: T) -> MallocBox<T> {
    MallocBox::<T>::new_in(x, MallocAllocator::new())
}

/// Allocate a [MallocVec] for the type `T`. No memory will be actually allocated
/// until elements are pushed to the vector.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::memsec::malloc::{malloc_vec, MallocVec};
/// let mut malloc_vec: MallocVec<u8> = malloc_vec();
/// malloc_vec.push(0u8);
/// malloc_vec.push(1u8);
/// malloc_vec.push(2u8);
/// # let mut element = malloc_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 2u8);
/// # element = malloc_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 1u8);
/// # element = malloc_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 0u8);
/// # element = malloc_vec.pop();
/// # assert!(element.is_none());
/// ```
pub fn malloc_vec<T>() -> MallocVec<T> {
    MallocVec::<T>::new_in(MallocAllocator::new())
}

impl MallocAllocator {
    /// Creates a new [MallocAllocator].
    pub fn new() -> Self {
        Self {
            _dummy_private_data: MallocAllocatorContents,
        }
    }
}

unsafe impl Allocator for MallocAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Call memsec allocator
        let mem: Option<NonNull<[u8]>> = unsafe { memsec::malloc_sized(layout.size()) };

        // Unwrap the option
        let Some(mem) = mem else {
            log::error!("Allocation {layout:?} was requested but memsec returned a null pointer");
            return Err(AllocError);
        };

        // Ensure the right alignment is used
        let off = (mem.as_ptr() as *const u8).align_offset(layout.align());
        if off != 0 {
            log::error!("Allocation {layout:?} was requested but malloc-based memsec returned allocation \
                with offset {off} from the requested alignment. Malloc always allocates values \
                at the end of a memory page for security reasons, custom alignments are not supported. \
                You could try allocating an oversized value.");
            unsafe { memsec::free(mem) };
            return Err(AllocError);
        };

        Ok(mem)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            memsec::free(ptr);
        }
    }
}

impl fmt::Debug for MallocAllocator {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<memsec based Rust allocator>")
    }
}

#[cfg(test)]
mod test {
    use allocator_api2_tests::make_test;

    use super::*;

    make_test! { test_sizes(MallocAllocator::new()) }
    make_test! { test_vec(MallocAllocator::new()) }
    make_test! { test_many_boxes(MallocAllocator::new()) }

    #[test]
    fn malloc_allocation() {
        let alloc = MallocAllocator::new();
        malloc_allocation_impl::<0>(&alloc);
        malloc_allocation_impl::<7>(&alloc);
        malloc_allocation_impl::<8>(&alloc);
        malloc_allocation_impl::<64>(&alloc);
        malloc_allocation_impl::<999>(&alloc);

        // Also test the debug-print for good measure
        let _ = format!("{:?}", alloc);
    }

    fn malloc_allocation_impl<const N: usize>(alloc: &MallocAllocator) {
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
