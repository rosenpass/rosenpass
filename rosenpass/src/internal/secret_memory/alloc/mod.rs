//! This module provides a [SecretAllocator](SecretAlloc) that allocates memory with extra
//! protections that make it more difficult for threat actors to access secrets that they aren't
//! authorized to access. At the moment the `memsec` and `memfdsec` allocators from the
//! [memsec] crate are supported for this purpose.
//!
//! [SecretAlloc] implements the [Allocator] trait and can thus be used as a drop in replacement
//! wherever this trait is required.
//!
//! The module also provides the [SecretVec] and [SecretBox] types.
pub mod memsec;

use std::sync::OnceLock;

use allocator_api2::alloc::{AllocError, Allocator};
use memsec::malloc::MallocAllocator;

#[cfg(target_os = "linux")]
use memsec::memfdsec::MemfdSecAllocator;

/// Caches automatic backend selection for the old allocator.
static ALLOC_TYPE: OnceLock<SecretAllocType> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SecretAllocType {
    MemsecMalloc,
    #[cfg(target_os = "linux")]
    MemsecMemfdSec,
}

/// An [Allocator] that automatically uses memfd-secret when available,
/// falling back to the memsec malloc backend otherwise.
pub struct SecretAlloc {
    alloc_type: SecretAllocType,
}

impl Default for SecretAlloc {
    fn default() -> Self {
        Self {
            alloc_type: *ALLOC_TYPE.get_or_init(|| {
                #[cfg(target_os = "linux")]
                let alloc_type = if memsec::memfdsec::memfdsec_box_try(0u8).is_ok() {
                    SecretAllocType::MemsecMemfdSec
                } else {
                    SecretAllocType::MemsecMalloc
                };
                #[cfg(not(target_os = "linux"))]
                let alloc_type = SecretAllocType::MemsecMalloc;

                log::info!("Secrets will be allocated using {alloc_type:?}");
                alloc_type
            }),
        }
    }
}

unsafe impl Allocator for SecretAlloc {
    fn allocate(
        &self,
        layout: std::alloc::Layout,
    ) -> Result<std::ptr::NonNull<[u8]>, allocator_api2::alloc::AllocError> {
        if layout.size() == 0 {
            return Ok(std::ptr::NonNull::slice_from_raw_parts(
                layout.dangling_ptr(),
                0,
            ));
        }

        match self.alloc_type {
            SecretAllocType::MemsecMalloc => MallocAllocator::default().allocate(layout),
            #[cfg(target_os = "linux")]
            SecretAllocType::MemsecMemfdSec => MemfdSecAllocator::default().allocate(layout),
        }
    }

    unsafe fn deallocate(&self, ptr: std::ptr::NonNull<u8>, layout: std::alloc::Layout) {
        if layout.size() == 0 {
            return;
        }

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
#[cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```rust,ignore")]
/// # use rosenpass::internal::secret_memory::alloc::{secret_box_try, SecretBox};
/// let data: u8 = 42;
/// let secret_box: SecretBox<u8> = secret_box_try(data)?;
/// # assert_eq!(*secret_box, 42u8);
/// # Ok::<(), anyhow::Error>(())
/// ```
pub fn secret_box_try<T>(x: T) -> Result<SecretBox<T>, AllocError> {
    SecretBox::<T>::try_new_in(x, SecretAlloc::default())
}

/// Allocates a [SecretBox] for the type `T`. If `T` is zero-sized the allocation
/// still works.
///
/// # Example
#[cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```rust,ignore")]
/// # use rosenpass::internal::secret_memory::alloc::{secret_box, SecretBox};
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
#[cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```rust,ignore")]
/// # use rosenpass::internal::secret_memory::alloc::{secret_vec, SecretVec};
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

#[cfg(test)]
mod test {
    use super::*;
    use crate::internal::secret_memory::Secret;

    #[test]
    fn secret_collections_need_no_policy() {
        assert_eq!(*secret_box(()), ());
        assert_eq!(*secret_box_try([42u8; 32]).unwrap(), [42; 32]);

        let mut bytes = secret_vec();
        bytes.extend(0..=255u8);
        bytes.resize(4097, 42);
        assert_eq!(&bytes[..256], &(0..=255u8).collect::<Vec<_>>());
        assert_eq!(&bytes[256..], &[42; 3841]);

        assert_eq!(Secret::<0>::zero().secret(), &[0u8; 0]);
        assert_eq!(Secret::<32>::zero().secret(), &[0; 32]);
    }
}
