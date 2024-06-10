#![cfg(target_os = "linux")]
use std::fmt;
use std::ptr::NonNull;

use allocator_api2::alloc::{AllocError, Allocator, Layout};

#[derive(Copy, Clone, Default)]
struct MemfdSecAllocatorContents;

/// Memory allocation using using the memsec crate
#[derive(Copy, Clone, Default)]
pub struct MemfdSecAllocator {
    _dummy_private_data: MemfdSecAllocatorContents,
}

/// A box backed by the memsec allocator
pub type MemfdSecBox<T> = allocator_api2::boxed::Box<T, MemfdSecAllocator>;

/// A vector backed by the memsec allocator
pub type MemfdSecVec<T> = allocator_api2::vec::Vec<T, MemfdSecAllocator>;

pub fn memfdsec_box_try<T>(x: T) -> Result<MemfdSecBox<T>, AllocError> {
    MemfdSecBox::<T>::try_new_in(x, MemfdSecAllocator::new())
}

pub fn memfdsec_box<T>(x: T) -> MemfdSecBox<T> {
    MemfdSecBox::<T>::new_in(x, MemfdSecAllocator::new())
}

pub fn memfdsec_vec<T>() -> MemfdSecVec<T> {
    MemfdSecVec::<T>::new_in(MemfdSecAllocator::new())
}

impl MemfdSecAllocator {
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
