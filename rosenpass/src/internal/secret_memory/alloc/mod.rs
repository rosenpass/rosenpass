//! Collections backed by the opportunistic [SecretMemoryAllocator].
//!
//! [SecretBox] and [SecretVec] use the standard library's allocator-aware collections.
//! Their constructors always use [SecretMemoryAllocator::default()], which prefers
//! memfd-secret when supported and permits anonymous mappings otherwise.
//!
//! Storage is wiped when deallocated, but removing individual elements does not
//! zeroize retained storage. [super::Secret] also zeroizes byte arrays before
//! returning their allocations to its reuse pool.

use std::alloc::{AllocError, Allocator, Layout};

use crate::internal::util::secret_memory::alloc::SecretMemoryAllocator;

/// A [Box] backed by the default [SecretMemoryAllocator].
pub type SecretBox<T> = Box<T, SecretMemoryAllocator>;

/// A [Vec] backed by the default [SecretMemoryAllocator].
pub type SecretVec<T> = Vec<T, SecretMemoryAllocator>;

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
    let alloc = SecretMemoryAllocator::default();
    let ptr = if std::mem::size_of::<T>() == 0 {
        std::ptr::NonNull::<T>::dangling()
    } else {
        alloc.allocate(Layout::new::<T>())?.cast::<T>()
    };
    // SAFETY: The allocation fits T and is initialized before ownership is
    // transferred to a Box using the same allocator.
    unsafe {
        ptr.as_ptr().write(x);
        Ok(Box::from_raw_in(ptr.as_ptr(), alloc))
    }
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
    SecretBox::<T>::new_in(x, SecretMemoryAllocator::default())
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
    SecretVec::<T>::new_in(SecretMemoryAllocator::default())
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

    #[test]
    fn secret_collections_use_default_allocator() {
        let boxed: Box<[u8; 32], SecretMemoryAllocator> = secret_box([42; 32]);
        assert_eq!(Box::allocator(&boxed), &SecretMemoryAllocator::default());

        let mut bytes: Vec<u8, SecretMemoryAllocator> = secret_vec();
        bytes.extend_from_slice(boxed.as_slice());
        bytes.resize(4097, 7);
        assert_eq!(&bytes[..32], &[42; 32]);
        assert_eq!(&bytes[32..], &[7; 4065]);

        bytes.truncate(32);
        let boxed = bytes.into_boxed_slice();
        assert_eq!(boxed.as_ref(), &[42; 32]);
        assert_eq!(Box::allocator(&boxed), &SecretMemoryAllocator::default());
    }

    #[test]
    fn secret_box_try_supports_overaligned_zero_sized_values() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        static DROPS: AtomicUsize = AtomicUsize::new(0);
        #[repr(align(131072))]
        struct Aligned;
        impl Drop for Aligned {
            fn drop(&mut self) {
                DROPS.fetch_add(1, Ordering::SeqCst);
            }
        }

        let boxed = secret_box_try(Aligned).expect("zero-sized values need no allocation");
        assert_eq!(std::ptr::from_ref(&*boxed).addr() % 131072, 0);
        assert_eq!(DROPS.load(Ordering::SeqCst), 0);
        drop(boxed);
        assert_eq!(DROPS.load(Ordering::SeqCst), 1);
    }
}
