use std::fmt;
use std::ptr::NonNull;

use allocator_api2::alloc::{AllocError, Allocator, Layout, Global};

#[derive(Copy, Clone, Default)]
struct MemsecAllocatorContents;

/// Memory allocation using using the memsec crate
#[derive(Copy, Clone, Default)]
pub struct MemsecAllocator {
    global: Global
}

/// A box backed by the memsec allocator
pub type MemsecBox<T> = allocator_api2::boxed::Box<T, MemsecAllocator>;

/// A vector backed by the memsec allocator
pub type MemsecVec<T> = allocator_api2::vec::Vec<T, MemsecAllocator>;

pub fn memsec_box<T>(x: T) -> MemsecBox<T> {
    MemsecBox::<T>::new_in(x, MemsecAllocator::new())
}

pub fn memsec_vec<T>() -> MemsecVec<T> {
    MemsecVec::<T>::new_in(MemsecAllocator::new())
}

impl MemsecAllocator {
    pub fn new() -> Self {
        Self {
            global: Global
        }
    }
}

unsafe impl Allocator for MemsecAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.global.allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe { self.global.deallocate(ptr, _layout) }
    }
}

impl fmt::Debug for MemsecAllocator {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<memsec based Rust allocator>")
    }
}

#[cfg(test)]
mod test {
    use allocator_api2_tests::make_test;

    use super::*;

    make_test! { test_sizes(MemsecAllocator::new()) }
    make_test! { test_vec(MemsecAllocator::new()) }
    make_test! { test_many_boxes(MemsecAllocator::new()) }

    #[test]
    fn memsec_allocation() {
        let alloc = MemsecAllocator::new();
        memsec_allocation_impl::<0>(&alloc);
        memsec_allocation_impl::<7>(&alloc);
        memsec_allocation_impl::<8>(&alloc);
        memsec_allocation_impl::<64>(&alloc);
        memsec_allocation_impl::<999>(&alloc);
    }

    fn memsec_allocation_impl<const N: usize>(alloc: &MemsecAllocator) {
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
