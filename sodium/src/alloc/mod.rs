//! Access to sodium_malloc/sodium_free

mod allocator;
pub use allocator::Alloc;

/// A box backed by sodium_malloc
pub type Box<T> = allocator_api2::boxed::Box<T, Alloc>;

/// A vector backed by sodium_malloc
pub type Vec<T> = allocator_api2::vec::Vec<T, Alloc>;
