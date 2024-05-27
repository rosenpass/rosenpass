use core::slice;
use std::fmt;
use std::process::abort;
use std::ptr::NonNull;

use allocator_api2::alloc::{AllocError, Allocator, Layout};

#[derive(Copy, Clone, Default)]
struct MemsecAllocatorContents;

/// Memory allocation using using the memsec crate
#[derive(Copy, Clone, Default)]
pub struct MemsecAllocator {
    _dummy_private_data: MemsecAllocatorContents,
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
            _dummy_private_data: MemsecAllocatorContents,
        }
    }
}

#[repr(u8)]
enum MemsecAllocType {
    Malloc = 0,
    #[cfg(target_os = "linux")]
    MemfdSecret = 1,
}

impl std::fmt::Display for MemsecAllocType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemsecAllocType::Malloc => write!(f, "memsec malloc()"),
            #[cfg(target_os = "linux")]
            MemsecAllocType::MemfdSecret => write!(f, "memsec memfd_secret()"),
        }
    }
}

unsafe impl Allocator for MemsecAllocator {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        let alloc_type_bytes = if layout.align() > 0 {
            layout.align()
        } else {
            1
        };
        let mem_size = alloc_type_bytes + layout.size();

        let mut alloc_type;

        #[cfg(target_os = "linux")]
        let mem: Option<NonNull<[u8]>> = {
            #[cfg(not(any(
                feature = "enable_memsec_malloc",
                feature = "enable_memsec_memfd_secret"
            )))]
            compile_error!("no allocator is enabled on this platform");

            // Try allocation with memfd_secret
            alloc_type = MemsecAllocType::MemfdSecret;

            let mut mem = {
                #[cfg(feature = "enable_memsec_memfd_secret")]
                unsafe {
                    memsec::memfd_secret_sized(mem_size)
                }
                #[cfg(not(feature = "enable_memsec_memfd_secret"))]
                None
            };

            if mem.is_none() {
                alloc_type = MemsecAllocType::Malloc;

                #[cfg(feature = "enable_memsec_memfd_secret")]
                log::warn!("memfd failed, trying malloc based allocation");

                mem = {
                    #[cfg(feature = "enable_memsec_malloc")]
                    unsafe {
                        memsec::malloc_sized(mem_size)
                    }
                    #[cfg(not(feature = "enable_memsec_malloc"))]
                    None
                };
            }
            mem
        };
        #[cfg(not(target_os = "linux"))]
        let mut mem = {
            #[cfg(not(feature = "enable_memsec_malloc"))]
            compile_error!("no allocator is enabled on this platform");

            alloc_type = MemsecAllocType::Malloc;
            unsafe { memsec::malloc_sized(mem_size) }
        };

        // Unwrap the option
        let Some(mem) = mem else {
            log::error!("Allocation {layout:?} was requested but memsec returned a null pointer");
            return Err(AllocError);
        };

        // Ensure the right alignment is used
        let off = (mem.as_ptr() as *const u8).align_offset(layout.align());
        if off != 0 {
            log::error!("Allocation {layout:?} was requested but memsec returned allocation \
                with offset {off} from the requested alignment. Memsec always allocates values \
                at the end of a memory page for security reasons, custom alignments are not supported. \
                You could try allocating an oversized value.");
            match alloc_type {
                MemsecAllocType::Malloc => unsafe { memsec::free(mem) },
                #[cfg(target_os = "linux")]
                MemsecAllocType::MemfdSecret => unsafe { memsec::free_memfd_secret(mem) },
            }
            return Err(AllocError);
        };

        // Add the allocation type to the start of the allocation
        let alloc_type_ptr = mem.as_ptr() as *mut u8;
        unsafe { alloc_type_ptr.write(alloc_type as u8) };
        let mem_ptr = unsafe { ((*mem.as_ptr())[alloc_type_bytes..]).as_ptr() } as *mut u8;

        let mem = unsafe {
            NonNull::new_unchecked(slice::from_raw_parts_mut(
                mem_ptr,
                mem.len() - alloc_type_bytes,
            ))
        };
        Ok(mem)
    }

    unsafe fn deallocate(&self, ptr: NonNull<u8>, layout: Layout) {
        let alloc_type_bytes = if layout.align() > 0 {
            layout.align()
        } else {
            1
        };

        let alloc_type_ptr = ptr.as_ptr().sub(alloc_type_bytes);

        let mem = unsafe {
            NonNull::new_unchecked(slice::from_raw_parts_mut(
                alloc_type_ptr,
                layout.size() + alloc_type_bytes,
            ))
        };

        match *alloc_type_ptr {
            v if v == MemsecAllocType::Malloc as u8 => unsafe { memsec::free(mem) },

            #[cfg(target_os = "linux")]
            v if v == MemsecAllocType::MemfdSecret as u8 => unsafe {
                memsec::free_memfd_secret(mem)
            },
            v => {
                log::error!("Unknown allocation type {:#x} found in deallocate", v);
                abort();
            }
        }
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
