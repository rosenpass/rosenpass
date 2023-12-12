use allocator_api2::alloc::{AllocError, Allocator, Layout};
use rand::{self, Rng};
use libc;
use std::fmt;
use std::mem::size_of;
use std::os::raw::c_void;
use std::ptr::{NonNull, null_mut};

/// A box backed by sodium_malloc
pub type Box<T> = allocator_api2::boxed::Box<T, Alloc>;

/// A vector backed by sodium_malloc
pub type Vec<T> = allocator_api2::vec::Vec<T, Alloc>;

/// Memory allocation using sodium_malloc/sodium_free
#[derive(Clone)]
pub struct Alloc {
    #[cfg(with_memfd_secret)]
    alloc: SecretAlloc,
    #[cfg(not(with_memfd_secret))]
    alloc: SodiumAlloc,
}

impl Alloc {
    #[cfg(with_memfd_secret)]
    pub fn new() -> Self {
        Alloc {
            alloc: SecretAlloc::new(),
        }
    }

    #[cfg(not(with_memfd_secret))]
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

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        self.alloc.do_deallocate(ptr, layout);
    }
}

impl Default for Alloc {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Alloc {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str("<libsodium based Rust allocator>")
    }
}

const CANARY_SIZE: usize = 16;
type CanaryType = [u8; CANARY_SIZE];

fn get_canary() -> &'static CanaryType {
    static CANARY: std::sync::OnceLock<CanaryType> = std::sync::OnceLock::new();
    // Canary is used to detect invalid write
    // So its value is meaningless
    // And random number is more secure to avoid attack fake it
    CANARY.get_or_init(|| {
        [rand::thread_rng().gen(); CANARY_SIZE]
    })
}

#[derive(Clone, Default)]
struct SodiumAlloc;

impl SodiumAlloc {
    fn do_allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        // Call sodium allocator
        let ptr = unsafe { Self::do_malloc(layout.size()) };

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
            Self::do_free(ptr.as_ptr() as *mut c_void);
        }
    }

    const PAGE_SIZE: usize = 0x10000;
    const PAGE_MASK: usize = Self::PAGE_SIZE - 1;

    // Reference libsodium, just convert to rust
    #[cfg(with_posix_memalign)]
    unsafe fn do_malloc(size: usize) -> *mut libc::c_void {
        // total memory region:
        // |PAGE|PAGE|unprotected|PAGE|
        let size_with_canary = size + CANARY_SIZE;
        let unprotected_size = Self::page_round(size_with_canary);
        let total_size = Self::PAGE_SIZE + Self::PAGE_SIZE + unprotected_size + Self::PAGE_SIZE;

        if size >= (std::usize::MAX - Self::PAGE_SIZE * 4) {
            return null_mut();
        }

        if Self::PAGE_SIZE <= CANARY_SIZE || Self::PAGE_SIZE < std::mem::size_of::<usize>() {
            Self::do_misuse();
        }

        let base_ptr = Self::do_alloc_aligned(total_size);
        let unprotected_ptr = base_ptr.add(Self::PAGE_SIZE * 2);

        Self::do_mem_protect_noaccess(base_ptr.add(Self::PAGE_SIZE), Self::PAGE_SIZE);
        Self::do_mem_protect_noaccess(unprotected_ptr.add(unprotected_size), Self::PAGE_SIZE);
        Self::do_mlock(unprotected_ptr, unprotected_size);
        let canary_ptr = unprotected_ptr.add(Self::page_round(size_with_canary)).sub(size_with_canary);
        let user_ptr = canary_ptr.add(CANARY_SIZE);
        unsafe {
            libc::memcpy(canary_ptr, get_canary().as_ptr() as *const libc::c_void, CANARY_SIZE);
            libc::memcpy(base_ptr, (&unprotected_size) as *const usize as *const libc::c_void , size_of::<usize>());
        }
        Self::do_mem_protect_readonly(base_ptr, Self::PAGE_SIZE);
        assert_eq!(Self::unprotected_ptr_from_user_ptr(user_ptr), unprotected_ptr);
        user_ptr
    }

    #[cfg(with_posix_memalign)]
    unsafe fn do_free(ptr: *mut libc::c_void) {
        if ptr == null_mut() {
            return;
        }
        let canary_ptr = ptr.sub(CANARY_SIZE);
        let unprotected_ptr = Self::unprotected_ptr_from_user_ptr(ptr);
        let base_ptr = unprotected_ptr.sub(Self::PAGE_SIZE * 2);
        let mut unprotected_size = 0;
        libc::memcpy(&mut unprotected_size as *mut usize as *mut libc::c_void, base_ptr, size_of::<usize>());
        let total_size = Self::PAGE_SIZE + Self::PAGE_SIZE + unprotected_size + Self::PAGE_SIZE;
        Self::do_mem_protect_readwrite(base_ptr, total_size);
        if libc::memcmp(canary_ptr, get_canary().as_ptr() as *const libc::c_void, CANARY_SIZE) != 0 {
            Self::do_out_of_bounds();
        }
        Self::do_munlock(unprotected_ptr, unprotected_size);
        Self::do_free_aligned(base_ptr, total_size);
    }

    #[cfg(not(with_posix_memalign))]
    unsafe fn do_malloc(size: usize) -> *mut libc::c_void {
        libc::malloc(size)
    }

    #[cfg(not(with_posix_memalign))]
    unsafe fn do_free(ptr: *mut libc::c_void) {
        libc::free(ptr);
    }

    fn page_round(size: usize) -> usize {
        return (size + Self::PAGE_MASK) & !Self::PAGE_MASK;
    }

    fn do_misuse() {
        panic!("Sodium malloc misuse.");
    }

    fn do_out_of_bounds() {
        panic!("Sodium memory out of bounds.");
    }

    #[cfg(with_posix_memalign)]
    fn do_alloc_aligned(size: usize) -> *mut libc::c_void {
        let mut ptr = null_mut();
        let ret = unsafe {
            libc::posix_memalign(&mut ptr, Self::PAGE_SIZE, size)
        };
        if ret != 0 {
            log::error!(
                "posix_memalign failed."
            );
            return null_mut();
        }
        ptr
    }

    fn do_free_aligned(ptr: *mut libc::c_void, _size: usize) {
        unsafe {
            libc::free(ptr);
        }
    }

    fn do_mem_protect_noaccess(ptr: *mut libc::c_void, size: usize) {
        let ret = unsafe {
            libc::mprotect(ptr, size, libc::PROT_NONE)
        };
        if ret != 0 {
            log::error!(
                "mprotect PROT_NONE failed."
            );
        }
    }

    fn do_mem_protect_readonly(ptr: *mut libc::c_void, size: usize) {
        let ret = unsafe {
            libc::mprotect(ptr, size, libc::PROT_READ)
        };
        if ret != 0 {
            log::error!(
                "mprotect PROT_READ failed."
            );
        }
    }

    fn do_mem_protect_readwrite(ptr: *mut libc::c_void, size: usize) {
        let ret = unsafe {
            libc::mprotect(ptr, size, libc::PROT_READ | libc::PROT_WRITE)
        };
        if ret != 0 {
            log::error!(
                "mprotect PROT_READ | PROT_WRITE failed."
            );
        }
    }

    fn do_mlock(ptr: *mut libc::c_void, size: usize) -> i32 {
        unsafe {
            libc::mlock(ptr, size)
        }
    }

    fn do_munlock(ptr: *mut libc::c_void, size: usize) -> i32 {
        unsafe {
            libc::munlock(ptr, size)
        }
    }

    fn unprotected_ptr_from_user_ptr(ptr: *const libc::c_void) -> *mut libc::c_void {
        let canary_ptr = unsafe { ptr.sub(CANARY_SIZE) };
        let unprotected_ptr_u = canary_ptr as usize & !Self::PAGE_MASK;
        if unprotected_ptr_u <= Self::PAGE_SIZE * 2 {
            Self::do_misuse();
        }
        unprotected_ptr_u as *mut libc::c_void
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
                "Create secret file descriptor failed {}.",
                std::io::Error::last_os_error()
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
