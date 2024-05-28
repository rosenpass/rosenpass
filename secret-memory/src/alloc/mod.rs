pub mod memsec;

use std::sync::OnceLock;

use allocator_api2::alloc::{AllocError, Allocator};
use memsec::malloc::MallocAllocator;

#[cfg(target_os = "linux")]
use memsec::memfdsec::MemfdSecAllocator;

static ALLOC_TYPE: OnceLock<SecretAllocType> = OnceLock::new();

/// Sets the secret allocation type to use.
/// Intended usage at startup before secret allocation
/// takes place
pub fn set_secret_alloc_type(alloc_type: SecretAllocType) {
    ALLOC_TYPE.set(alloc_type).unwrap();
}

///
pub fn get_or_init_secret_alloc_type(alloc_type: SecretAllocType) -> SecretAllocType {
    *ALLOC_TYPE.get_or_init(|| alloc_type)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretAllocType {
    MemsecMalloc,
    #[cfg(target_os = "linux")]
    MemsecMemfdSec,
}

pub struct SecretAlloc {
    alloc_type: SecretAllocType,
}

impl SecretAlloc {
    pub fn new() -> Self {
        Self {
            alloc_type: *ALLOC_TYPE.get().expect("Secret security policy not specified. Run the specifying policy function in rosenpass_secret_memory::policy or set a custom policy by initializing rosenpass_secret_memory::alloc::ALLOC_TYPE before using secrets"),
        }
    }
}

unsafe impl Allocator for SecretAlloc {
    fn allocate(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        match self.alloc_type {
            SecretAllocType::MemsecMalloc => MallocAllocator::new().allocate(layout),
            #[cfg(target_os = "linux")]
            SecretAllocType::MemsecMemfdSec => MemfdSecAllocator::new().allocate(layout),
        }
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) {
        match self.alloc_type {
            SecretAllocType::MemsecMalloc => MallocAllocator::new().deallocate(ptr, layout),
            #[cfg(target_os = "linux")]
            SecretAllocType::MemsecMemfdSec => MemfdSecAllocator::new().deallocate(ptr, layout),
        }
    }
}

pub type SecretBox<T> = allocator_api2::boxed::Box<T, SecretAlloc>;

/// A vector backed by the memsec allocator
pub type SecretVec<T> = allocator_api2::vec::Vec<T, SecretAlloc>;

pub fn sec_box_try<T>(x: T) -> Result<SecretBox<T>, AllocError> {
    SecretBox::<T>::try_new_in(x, SecretAlloc::new())
}

pub fn secret_box<T>(x: T) -> SecretBox<T> {
    SecretBox::<T>::new_in(x, SecretAlloc::new())
}

pub fn secret_vec<T>() -> SecretVec<T> {
    SecretVec::<T>::new_in(SecretAlloc::new())
}
