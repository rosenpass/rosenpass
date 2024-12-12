//! This module provides a [SecretAllocator](SecretAlloc) that allocates memory with extra
//! protections that make it more difficult for threat actors to access secrets that they aren't
//! authorized to access. At the moment the `memsec` and `memfdsec` allocators from the
//! [memsec] crate are supported for this purpose.
//!
//! [SecretAlloc] implements the [Allocator] trait and can thus be used as a drop in replacement
//! wherever ever this trait is required.
//!
//! The module also provides the [SecretVec] and [SecretBox] types.
pub mod memsec;

use std::sync::OnceLock;

use allocator_api2::alloc::{AllocError, Allocator};
use memsec::malloc::MallocAllocator;

#[cfg(target_os = "linux")]
use memsec::memfdsec::MemfdSecAllocator;

/// Globally configures which [SecretAllocType] to use as default for
/// [SecretAllocators](SecretAlloc).
static ALLOC_TYPE: OnceLock<SecretAllocType> = OnceLock::new();

/// Sets the secret allocation type to use by default for [SecretAllocators](SecretAlloc).
/// It is intended that this function is called at startup before a secret allocation
/// takes place.
///
/// # Example
/// ```rust
/// # use std::alloc::Layout;
/// # use allocator_api2::alloc::Allocator;
/// # use rosenpass_secret_memory::alloc::{set_secret_alloc_type, SecretAlloc, SecretAllocType};
/// # fn do_test () -> Result<(), Box<dyn std::error::Error>> {
/// set_secret_alloc_type(SecretAllocType::MemsecMalloc);
/// let secret_alloc = SecretAlloc::default();
/// unsafe {
///     let memory = secret_alloc.allocate(Layout::from_size_align_unchecked(42, 64))?;
/// }
/// # Ok(())
/// # }
/// ```
pub fn set_secret_alloc_type(alloc_type: SecretAllocType) {
    ALLOC_TYPE.set(alloc_type).unwrap();
}

/// Initializes [ALLOC_TYPE] with `alloc_type` if it is not initialized yet. Returns
/// the current [SecretAllocType] afterward.
///
/// # Example
/// ```rust
/// # use std::alloc::Layout;
/// # use allocator_api2::alloc::Allocator;
/// # use rosenpass_secret_memory::alloc::{get_or_init_secret_alloc_type, set_secret_alloc_type,
/// # SecretAlloc, SecretAllocType};
/// set_secret_alloc_type(SecretAllocType::MemsecMalloc);
/// let alloc_typpe = get_or_init_secret_alloc_type(SecretAllocType::MemsecMemfdSec);
/// assert_eq!(alloc_typpe, SecretAllocType::MemsecMalloc);
///```
pub fn get_or_init_secret_alloc_type(alloc_type: SecretAllocType) -> SecretAllocType {
    *ALLOC_TYPE.get_or_init(|| alloc_type)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretAllocType {
    MemsecMalloc,
    #[cfg(target_os = "linux")]
    MemsecMemfdSec,
}

/// An [Allocator] that uses a [SecretAllocType] for allocation.
pub struct SecretAlloc {
    alloc_type: SecretAllocType,
}

impl Default for SecretAlloc {
    fn default() -> Self {
        Self {
            alloc_type: *ALLOC_TYPE.get().expect(
                "Secret security policy not specified. \
                Run the specifying policy function in \
                 rosenpass_secret_memory::policy or set a \
                 custom policy by initializing \
                 rosenpass_secret_memory::alloc::ALLOC_TYPE \
                 before using secrets",
            ),
        }
    }
}

unsafe impl Allocator for SecretAlloc {
    fn allocate(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        match self.alloc_type {
            SecretAllocType::MemsecMalloc => MallocAllocator::default().allocate(layout),
            #[cfg(target_os = "linux")]
            SecretAllocType::MemsecMemfdSec => MemfdSecAllocator::default().allocate(layout),
        }
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) {
        match self.alloc_type {
            SecretAllocType::MemsecMalloc => MallocAllocator::default().deallocate(ptr, layout),
            #[cfg(target_os = "linux")]
            SecretAllocType::MemsecMemfdSec => MemfdSecAllocator::default().deallocate(ptr, layout),
        }
    }
}

/// A [allocator_api2::boxed::Box] that is backed by [SecretAlloc].
pub type SecretBox<T> = allocator_api2::boxed::Box<T, SecretAlloc>;

/// A [allocator_api2::vec::Vec] that is backed by [SecretAlloc].
pub type SecretVec<T> = allocator_api2::vec::Vec<T, SecretAlloc>;

/// Try to allocate a [SecretBox] for the type `T`. If `T` is zero-sized the allocation
/// still works. It returns an error if the allocation fails.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::{secret_box_try, SecretBox};
/// # use rosenpass_secret_memory::alloc::SecretAllocType::MemsecMalloc;
/// # use rosenpass_secret_memory::alloc::set_secret_alloc_type;
/// set_secret_alloc_type(MemsecMalloc);
/// # fn do_test() -> Result<(), Box<dyn std::error::Error>> {
/// let data: u8 = 42;
/// let secret_box: SecretBox<u8> = secret_box_try(data)?;
/// # assert_eq!(*secret_box, 42u8);
/// # Ok(())
/// # }
/// ```
pub fn secret_box_try<T>(x: T) -> Result<SecretBox<T>, AllocError> {
    SecretBox::<T>::try_new_in(x, SecretAlloc::default())
}

/// Allocates a [SecretBox] for the type `T`. If `T` is zero-sized the allocation
/// still works.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::{secret_box, SecretBox};
/// # use rosenpass_secret_memory::alloc::SecretAllocType::MemsecMalloc;
/// # use rosenpass_secret_memory::alloc::set_secret_alloc_type;
/// set_secret_alloc_type(MemsecMalloc);
/// let data: u8 = 42;
/// let secret_box: SecretBox<u8> = secret_box(data);
/// # assert_eq!(*secret_box, 42u8);
/// ```
pub fn secret_box<T>(x: T) -> SecretBox<T> {
    SecretBox::<T>::new_in(x, SecretAlloc::default())
}

/// Allocate a [SecretVec] for the type `T`. No memory will be actually allocated
/// until elements are pushed to the vector.
///
/// # Example
/// ```rust
/// # use rosenpass_secret_memory::alloc::{secret_vec, SecretVec};
/// # use rosenpass_secret_memory::alloc::SecretAllocType::MemsecMalloc;
/// # use rosenpass_secret_memory::alloc::set_secret_alloc_type;
/// set_secret_alloc_type(MemsecMalloc);
/// let mut secret_vec: SecretVec<u8> = secret_vec();
/// secret_vec.push(0u8);
/// secret_vec.push(1u8);
/// secret_vec.push(2u8);
/// # let mut element = secret_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 2u8);
/// # element = secret_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 1u8);
/// # element = secret_vec.pop();
/// # assert!(element.is_some());
/// # assert_eq!(element.unwrap(), 0u8);
/// # element = secret_vec.pop();
/// # assert!(element.is_none());
/// ```
pub fn secret_vec<T>() -> SecretVec<T> {
    SecretVec::<T>::new_in(SecretAlloc::default())
}
