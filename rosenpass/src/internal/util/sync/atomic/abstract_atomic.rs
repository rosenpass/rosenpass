//! Traits for types with atomic access semantics

use std::sync::atomic::Ordering;

/// A trait for types with atomic access semantics
///
/// Using this trait allows us to achieve two goals:
///
/// 1. We can implement atomic semantics for types where
///    there is no platform support for atomic semantics
///    (e.g. by using a [std::sync::Mutex])
/// 2. We can reuse implementations of concurrent data structures
///    efficiently for the non-concurrent case. E.g. we could
///    build a thread-local ring buffer by supplying some sort of
///    `Immediate<u64>` type for the atomics that implements
///    this trait by using a [std::cell::Cell]. It may seem
///    counterintuitive, but this setup implements perfectly fine atomic-appearing
///    semantics just as long as the cell is thread-local.
///
/// Note that implementing this trait is NOT necessarily sufficient for using
/// a type for concurrent access between threads or processes precisely because
/// the interface is also allowed to be implemented using [std::cell::Cell] (for truly
/// single-threaded uses) or [std::sync::Mutex] (for multi-threaded use).
///
/// So implementing/supplying this type does not directly imply that accesses are using atomic
/// semantics implemented in hardware; instead it allows developers to build algorithms and data
/// structures which may or may not be cross-thread synchronized; this way, the same data structure
/// implementation can be used in a thread-safe and thread-local context. The algorithm is
/// written in such a way that it could use atomics, specifying proper memory orderings for all
/// data accesses. In multi-threaded use, actual atomics would be supplied as implementation for [AbstractAtomic]
/// and the memory orderings would be meaningful. In single-threaded use, an implementation based
/// on [std::cell::Cell] could be used; this implementation would ignore the memory orderings.
///
/// With respect to single-threaded use, an implementation based on [std::cell::Cell] would still
/// be effectively atomic; the thread using it can never actually observe intermediate/undefined
/// states of the underlying atomic value, except that this guarantee is not enforced by atomic
/// memory access; the non-concurrent Rust language semantics are sufficient to provide this
/// guarantee.
pub trait AbstractAtomic<T> {
    /// Like [std::sync::atomic::AtomicU64::load()]
    fn load(&self, order: Ordering) -> T;

    /// Like [std::sync::atomic::AtomicU64::compare_exchange_weak()].
    ///
    /// The default implementation just calls [AbstractAtomic::compare_exchange()].
    fn compare_exchange_weak(
        &self,
        current: T,
        new: T,
        success: Ordering,
        failure: Ordering,
    ) -> Result<T, T> {
        self.compare_exchange(current, new, success, failure)
    }

    /// Like [std::sync::atomic::AtomicU64::compare_exchange()].
    fn compare_exchange(
        &self,
        current: T,
        new: T,
        success: Ordering,
        failure: Ordering,
    ) -> Result<T, T>;
}

/// Implements a default type for [AbstractAtomic]
///
/// This in essence is to [AbstractAtomic], as [std::ops::Deref] is to [std::borrow::Borrow];
/// the same functionality, except with an associated value type.
pub trait AbstractAtomicType: AbstractAtomic<Self::ValueType> {
    /// The underlying atomic value
    type ValueType;
}

/// Implementing [AbstractAtomic] and [AbstractAtomicType] for standard atomics
macro_rules! impl_abstract_atomic_for_atomic {
    ($($Atomic:ty : $Value:ty),*) => {
        $(
            impl AbstractAtomicType for $Atomic {
                type ValueType = $Value;
            }

            impl AbstractAtomic<$Value> for $Atomic {
                fn load(&self, order: Ordering) -> $Value {
                    <$Atomic>::load(&self, order)
                }

                fn compare_exchange_weak(
                    &self,
                    current: $Value,
                    new: $Value,
                    success: Ordering,
                    failure: Ordering,
                ) -> Result<$Value, $Value> {
                    <$Atomic>::compare_exchange_weak(&self, current, new, success, failure)
                }

                fn compare_exchange(
                    &self,
                    current: $Value,
                    new: $Value,
                    success: Ordering,
                    failure: Ordering,
                ) -> Result<$Value, $Value> {
                    <$Atomic>::compare_exchange(&self, current, new, success, failure)
                }
            }
        )*
    };
}

impl_abstract_atomic_for_atomic! {
    std::sync::atomic::AtomicBool: bool,
    std::sync::atomic::AtomicI8: i8,
    std::sync::atomic::AtomicI16: i16,
    std::sync::atomic::AtomicI32: i32,
    std::sync::atomic::AtomicI64: i64,
    std::sync::atomic::AtomicIsize: isize,
    std::sync::atomic::AtomicU8: u8,
    std::sync::atomic::AtomicU16: u16,
    std::sync::atomic::AtomicU32: u32,
    std::sync::atomic::AtomicU64: u64,
    std::sync::atomic::AtomicUsize: usize
}
