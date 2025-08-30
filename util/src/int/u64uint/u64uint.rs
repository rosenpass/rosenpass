//! The [U64UInt type]

use super::MAX_U64_IN_USIZE;

/// Error produced by [U64USize::try_new]
#[derive(Debug, thiserror::Error)]
pub enum U64USizeConversionError<T: std::fmt::Debug> {
    /// Value can not be represented as u64
    #[error("Value can not be represented as a u64 (max = {}) value: {:?}", u64::MAX, .0)]
    NoU64Repr(T),
    /// Value can not be represented as usize
    #[error("Value can not be represented as a usize (max = {}) value: {:?}", usize::MAX, .0)]
    NoUSizeRepr(T),
    /// Value can not be represented as usize or u64
    #[error("Value can not be represented as a u64 (max = {}) or usize (max = {}) value: {:?}", u64::MAX, usize::MAX, .0)]
    NoU64OrUSizeRepr(T),
}

/// A number that can be represented as both a usize and a u64.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct U64USize {
    /// Enclosed data
    storage: u64,
}

impl U64USize {
    /// Cast another number to a number that can be represented as usize and u64;
    ///
    /// This is the internal version which does not use [TryInto]; we use this to implement
    /// [TryInto].
    fn try_new_internal<T>(v: T) -> Result<Self, U64USizeConversionError<T>>
    where
        T: Copy + TryInto<usize> + TryInto<u64> + std::fmt::Debug,
    {
        use U64USizeConversionError as E;

        let v_u64: Result<u64, _> = v.try_into();
        let v_usize: Result<usize, _> = v.try_into();
        match (v_u64, v_usize) {
            (Ok(storage), Ok(_)) => Ok(Self { storage }),
            (Err(_), Ok(_)) => Err(E::NoU64Repr(v)),
            (Ok(_), Err(_)) => Err(E::NoUSizeRepr(v)),
            (Err(_), Err(_)) => Err(E::NoU64OrUSizeRepr(v)),
        }
    }

    /// Cast another number to a number that can be represented as usize and u64
    pub fn try_new<T>(v: T) -> Result<U64USize, <T as TryInto<Self>>::Error>
    where
        T: TryInto<Self>,
    {
        v.try_into()
    }

    /// Like [Self::try_new], but panics
    pub fn new_or_panic<T>(v: T) -> Self
    where
        T: TryInto<Self>,
        <T as TryInto<Self>>::Error: std::fmt::Debug,
    {
        match Self::try_new(v) {
            Ok(v) => v,
            Err(e) => panic!(
                "Could not construct {}: {e:?}",
                std::any::type_name::<Self>()
            ),
        }
    }

    /// Return this value as a usize
    pub fn usize(&self) -> usize {
        self.storage as usize
    }

    /// Return this value as a u64
    pub fn u64(&self) -> u64 {
        self.storage
    }
}

impl std::ops::Sub for U64USize {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        Self::new_or_panic(self.u64() - rhs.u64())
    }
}

impl std::ops::Add for U64USize {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self::new_or_panic(self.u64() + rhs.u64())
    }
}

/// Facilitates creation of [U64USize] in cases where truncation to the largest representable value is permissible
pub trait TruncateIntoU64USize {
    /// Check whether calling [TruncateIntoU64Usize::truncate_to_u64usize] would truncate or return
    /// the value as-is
    fn fits_into_u64usize(&self) -> bool;

    /// Turn [Self] into a [U64USize]. If the value is representable as a usize and a u64, then
    /// the value will be returned as is. Otherwise, the maximum representable value [MAX_U64_IN_USIZE]
    /// will be returned.
    fn truncate_to_u64usize(&self) -> U64USize;
}

/// Create instances of From for SafeUSize
macro_rules! derive_TruncateIntoU64Usize {
    ($($T:ty),*) => {
        $(
            impl TruncateIntoU64USize for $T {
                fn fits_into_u64usize(&self) -> bool {
                    U64USize::try_new(*self).is_ok()
                }

                fn truncate_to_u64usize(&self) -> U64USize {
                    U64USize::try_new(*self).unwrap_or(U64USize::new_or_panic(MAX_U64_IN_USIZE))
                }
            }
        )*
    }
}

derive_TruncateIntoU64Usize!(
    U64USize, usize, isize, bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128
);

/// Create instances of From for SafeUSize
macro_rules! U64USize_derive_from {
    ($($T:ty),*) => {
        $(
            impl From<$T> for U64USize {
                fn from(value: $T) -> Self {
                    U64USize::try_new_internal::<$T>(value).unwrap()
                }
            }
        )*
    }
}

U64USize_derive_from!(bool, u8, u16);

/// Create instances of TryFrom for SafeUSize
macro_rules! U64USize_derive_try_from {
    ($($T:ty),*) => {
        $(
            impl TryFrom<$T> for U64USize {
                type Error = U64USizeConversionError<$T>;

                fn try_from(value: $T) -> Result<Self, Self::Error> {
                    U64USize::try_new_internal::<$T>(value)
                }
            }
        )*
    }
}

U64USize_derive_try_from!(usize, isize, u32, u64, u128, i8, i16, i32, i64, i128);

/// Create instances of Into for SafeUSize
macro_rules! U64USize_derive_into {
    ($($T:ty),*) => {
        $(
            impl From<U64USize> for $T {
                fn from(val: U64USize) -> Self {
                    val.u64() as $T
                }
            }
        )*
    }
}

U64USize_derive_into!(usize, u64, u128, i128);

/// Create instances of TryInto for SafeUSize
macro_rules! U64USize_derive_try_into {
    ($($T:ty),*) => {
        $(
            impl TryFrom<U64USize> for $T {
                type Error = <$T as TryFrom<u64>>::Error;

                fn try_from(val: U64USize) -> Result<Self, Self::Error> {
                    val.u64().try_into()
                }
            }
        )*
    }
}

U64USize_derive_try_into!(isize, u8, u16, u32, i8, i16, i32, i64);
