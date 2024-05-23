use core::slice;
use std::process::abort;
use std::ptr::NonNull;
use std::{fmt, path::Display};

use allocator_api2::alloc::{AllocError, Allocator, Layout};
const USIZE_BYTES: usize = usize::BITS as usize / 8;

pub struct MultiAlloc {
    allocators: Vec<Box<dyn Allocator>>,
}

/// A box backed by MultiAlloc allocator
pub type MultiAllocBox<T> = allocator_api2::boxed::Box<T, MultiAlloc>;

/// A vector backed by MultiAlloc allocator
pub type MultiAllocVec<T> = allocator_api2::vec::Vec<T, MultiAlloc>;

impl MultiAlloc {
    pub fn new(allocators: Vec<Box<dyn Allocator>>) -> Self {
        Self { allocators }
    }
}

unsafe impl Allocator for MultiAlloc {
    fn allocate(&self, layout: Layout) -> Result<NonNull<[u8]>, AllocError> {
        //Align the allocation type to the maximum alignment
        let alloc_type_bytes = (USIZE_BYTES / layout.align())
            + (if USIZE_BYTES % layout.align() > 0 {
                1
            } else {
                0
            });

        let mem_size = alloc_type_bytes + layout.size();

        let mut alloc_type = None;

        let mem = self
            .allocators
            .iter()
            .enumerate()
            .find_map(|(idx, allocator)| {
                match allocator
                    .allocate(Layout::from_size_align(mem_size, alloc_type_bytes).unwrap())
                {
                    Ok(mem) => {
                        alloc_type = Some(idx);
                        Some(mem)
                    }
                    Err(_) => None,
                }
            });

        let Some(mem) = mem else {
            log::error!("Allocation {layout:?} was requested but no allocator could satisfy it");
            return Err(AllocError);
        };

        let Some(alloc_type) = alloc_type else {
            //This shouldn't really happen
            log::error!("Allocation {layout:?} was requested but no allocator could satisfy it");
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
        //Align the allocation type to the maximum alignment
        let alloc_type_bytes = (USIZE_BYTES / layout.align())
            + (if USIZE_BYTES % layout.align() > 0 {
                1
            } else {
                0
            });

        let mem_size = alloc_type_bytes + layout.size();

        let alloc_type_ptr = ptr.as_ptr().sub(alloc_type_bytes);

        let mem =
            unsafe { NonNull::new_unchecked(slice::from_raw_parts_mut(alloc_type_ptr, mem_size)) };

        let alloc_type = unsafe { *(alloc_type_ptr as *const usize) };

        if let Some(allocator) = self.allocators.get(alloc_type) {
            allocator.deallocate(
                mem,
                Layout::from_size_align(mem_size, alloc_type_bytes).unwrap(),
            );
        } else {
            log::error!("Deallocating {layout:?} was requested but no allocator could satisfy it");
        }
    }
}
