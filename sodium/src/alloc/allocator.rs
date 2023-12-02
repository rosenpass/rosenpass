use allocator_api2::alloc::{AllocError, Allocator, Layout};
use libsodium_sys as libsodium;
use libc;
use std::fmt;
use std::os::raw::c_void;
use std::ptr::{NonNull, null_mut};

/// Memory allocation using sodium_malloc/sodium_free
#[derive(Clone, Default)]
pub struct Alloc {
    alloc: SodiumAlloc,
}

impl Alloc {
    pub fn new() -> Self {
        Alloc {
            alloc: SodiumAlloc::default(),
        }
    }

}

unsafe impl Allocator for Alloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        self.alloc.do_allocate(layout)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        self.alloc.do_deallocate(ptr, _layout);
    }
}

impl fmt::Debug for Alloc {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<libsodium based Rust allocator>")
    }
}

#[derive(Clone, Default)]
struct SodiumAlloc;

impl SodiumAlloc {
    fn do_allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
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

    fn do_deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            libsodium::sodium_free(ptr.as_ptr() as *mut c_void);
        }
    }
}


#[derive(Clone)]
struct SecretAlloc {
    fd : i32,
}

impl SecretAlloc {
    pub fn new() -> Self {
        let fd  = unsafe {
            libc::syscall(libc::SYS_memfd_secret, 0) as i32
        };
        if fd == -1 {
            panic!(
                "Create secret file descriptor failed."
            );
        }
        SecretAlloc {
            fd: fd,
        }
    }

    fn do_allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let ptr = unsafe {
            let ret = libc::mmap(null_mut::<libc::c_void>(), layout.size(), libc::PROT_READ | libc::PROT_WRITE, libc::MAP_LOCKED, self.fd, 0);
            if ret == libc::MAP_FAILED {
                log::error!(
                    "mmap failed."
                );
                return Err(AllocError);
            } else {
                ret
            }
        };
        let off = ptr.align_offset(layout.align());
        if off != 0 {
            log::error!("Allocation {layout:?} was requested but mmap returned allocation \
                with offset {off} from the requested alignment. mmap always allocates values \
                at the end of a memory page for security reasons, custom alignments are not supported. \
                You could try allocating an oversized value.");
            Err(AllocError)
        } else {
            let ptr = core::ptr::slice_from_raw_parts_mut(ptr as *mut u8, layout.size());
            match NonNull::new(ptr) {
                None => {
                    // Allocate failure have been processed in mmap.
                    unreachable!()
                }
                Some(p) => Ok(p),
            }
        }
    }

    fn do_deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        unsafe {
            libc::munmap(ptr.as_ptr() as *mut libc::c_void, layout.size());
        }
    }
}

impl Default for SecretAlloc {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for SecretAlloc {
    fn drop(&mut self) {
        unsafe {
            libc::close(self.fd);
        }       
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
