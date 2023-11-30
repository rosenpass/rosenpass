use allocator_api2::alloc::{AllocError, Allocator, Layout};
use libsodium_sys as libsodium;
use std::fmt;
use std::os::raw::c_void;
use std::ptr::NonNull;

#[derive(Clone, Default)]
struct AllocatorContents;

/// Memory allocation using sodium_malloc/sodium_free
#[derive(Clone, Default)]
pub struct Alloc {
    _dummy_private_data: AllocatorContents,
}

impl Alloc {
    pub fn new() -> Self {
        Alloc {
            _dummy_private_data: AllocatorContents,
        }
    }
}

unsafe impl Allocator for Alloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Call sodium allocator
        let ptr = unsafe { libsodium::sodium_malloc(layout.size()) };

        // Ensure the right allocation is used
        let off = ptr.align_offset(layout.align());
        if off != 0 {
            log::error!("Allocation {layout:?} was requested but libsodium returned allocation \
                with offset {off} from the requested alignment. Libsodium always allocates values \
                at the end of a memory page for security reasons, custom alignments are not supported. \
                You could try allocating an oversized value.");
            return Err(AllocError);
        }

        // Convert to a pointer size
        let ptr = core::ptr::slice_from_raw_parts_mut(ptr as *mut u8, layout.size());

        // Conversion to a *const u8, then to a &[u8]
        match NonNull::new(ptr) {
            None => {
                log::error!(
                    "Allocation {layout:?} was requested but libsodium returned a null pointer"
                );
                Err(AllocError)
            }
            Some(ret) => Ok(ret),
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            libsodium::sodium_free(ptr.as_ptr() as *mut c_void);
        }
    }
}

impl fmt::Debug for Alloc {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<libsodium based Rust allocator>")
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// checks that the can malloc with libsodium
    #[test]
    fn sodium_allocation() {
        crate::init().unwrap();
        let alloc = Alloc::new();
        sodium_allocation_impl::<0>(&alloc);
        sodium_allocation_impl::<7>(&alloc);
        sodium_allocation_impl::<8>(&alloc);
        sodium_allocation_impl::<64>(&alloc);
        sodium_allocation_impl::<999>(&alloc);
    }

    fn sodium_allocation_impl<const N: usize>(alloc: &Alloc) {
        crate::init().unwrap();
        let layout = Layout::new::<[u8; N]>();
        let mem = alloc.allocate(layout).unwrap();

        // https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations
        // promises us that allocated memory is initialized with the magic byte 0xDB
        assert_eq!(unsafe { mem.as_ref() }, &[0xDBu8; N]);

        let mem = NonNull::new(mem.as_ptr() as *mut u8).unwrap();
        unsafe { alloc.deallocate(mem, layout) };
    }
}
