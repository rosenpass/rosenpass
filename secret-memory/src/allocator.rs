use allocator_api2::alloc::{AllocError, Allocator, Layout};
use libc;
use memsec;
use std::fmt;
use std::io::Error;
use std::ptr::{NonNull, null_mut};

/// A box backed by sodium_malloc
pub type Box<T> = allocator_api2::boxed::Box<T, Alloc>;

/// A vector backed by sodium_malloc
pub type Vec<T> = allocator_api2::vec::Vec<T, Alloc>;

/// Memory allocation using sodium_malloc/sodium_free
#[derive(Clone)]
pub struct Alloc {
    inner: AllocInner
}

#[derive(Clone)]
enum AllocInner {
    SecretAlloc(SecretAlloc),
    SodiumAlloc(SodiumAlloc),
}

impl Alloc {
    pub fn new() -> Self {
        Alloc {
            inner: if get_support_memfd_secret() {
                AllocInner::SecretAlloc(SecretAlloc::new())
            } else {
                AllocInner::SodiumAlloc(SodiumAlloc::default())
            }
        }
    }
}

unsafe impl Allocator for Alloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        match &self.inner {
            AllocInner::SecretAlloc(alloc) => alloc.do_allocate(layout),
            AllocInner::SodiumAlloc(alloc) => alloc.do_allocate(layout),
        }
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        match &self.inner {
            AllocInner::SecretAlloc(alloc) => alloc.do_deallocate(ptr, layout),
            AllocInner::SodiumAlloc(alloc) => alloc.do_deallocate(ptr, layout),
        }
    }
}

impl Default for Alloc {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Alloc {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        match &self.inner {
            AllocInner::SecretAlloc(_) => fmt.write_str("<memfd_secret based Rust allocator>"),
            AllocInner::SodiumAlloc(_) => fmt.write_str("<memsec based Rust allocator>")
        }
    }
}

#[cfg(not(unix))]
fn get_support_memfd_secret() -> bool {
    false
}

#[cfg(unix)]
fn get_support_memfd_secret() -> bool {
    static SUPPORT_MEMFD_SECRET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *SUPPORT_MEMFD_SECRET.get_or_init(|| {
        let fd  = unsafe {
            libc::syscall(libc::SYS_memfd_secret, 0) as i32
        };
        if fd != -1 || if let Some(os_err) = Error::last_os_error().raw_os_error() { os_err != 38 } else { true } {
            // with memfd_secret support
            return true;
        }
        if fd != -1 {
            unsafe {
                libc::close(fd);
            }
        }
        false
    })
}

#[derive(Clone, Default)]
struct SodiumAlloc;

impl SodiumAlloc {
    fn do_allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Call sodium allocator
        let ptr = unsafe { memsec::malloc_sized(layout.size()) };

        let ptr = if let Some(p) = ptr {
            p
        } else {
            log::error!(
                "Allocation {layout:?} was requested but memsec returned a null pointer"
            );
            return Err(AllocError);
        };

        // Ensure the right allocation is used
        let off = (ptr.as_ptr() as *const libc::c_void).align_offset(layout.align());
        if off != 0 {
            log::error!("Allocation {layout:?} was requested but memsec returned allocation \
                with offset {off} from the requested alignment. Memsec always allocates values \
                at the end of a memory page for security reasons, custom alignments are not supported. \
                You could try allocating an oversized value.");
            return Err(AllocError);
        }

        Ok(ptr)
    }

    fn do_deallocate(&self, ptr: NonNull<u8>, _layout: Layout) {
        unsafe {
            memsec::free(ptr)
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
            log::error!(
                "Create secret file descriptor failed {}.",
                std::io::Error::last_os_error()
            );
        }
        SecretAlloc {
            fd: fd,
        }
    }

    fn do_allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        if self.fd == -1 {
            log::error!(
                "Create secret file descriptor failed."
            );
            return Err(AllocError);
        }
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
        if self.fd == -1 {
            log::error!(
                "Create secret file descriptor failed."
            );
            return;
        }
        unsafe {
            libc::munmap(ptr.as_ptr() as *mut libc::c_void, layout.size());
        }
    }
}

impl Drop for SecretAlloc {
    fn drop(&mut self) {
        if self.fd != -1 {
            unsafe {
                libc::close(self.fd);
            }       
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// checks that the can malloc with libsodium
    #[test]
    fn sodium_allocation() {
        let alloc = Alloc::new();
        sodium_allocation_impl::<0>(&alloc);
        sodium_allocation_impl::<7>(&alloc);
        sodium_allocation_impl::<8>(&alloc);
        sodium_allocation_impl::<64>(&alloc);
        sodium_allocation_impl::<999>(&alloc);
    }

    fn sodium_allocation_impl<const N: usize>(alloc: &Alloc) {
        let layout = Layout::new::<[u8; N]>();
        let mem = alloc.allocate(layout).unwrap();

        // https://libsodium.gitbook.io/doc/memory_management#guarded-heap-allocations
        // promises us that allocated memory is initialized with the magic byte 0xDB
        assert_eq!(unsafe { mem.as_ref() }, &[0xDBu8; N]);

        let mem = NonNull::new(mem.as_ptr() as *mut u8).unwrap();
        unsafe { alloc.deallocate(mem, layout) };
    }
}
