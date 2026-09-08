//! The [U64USize] type

use super::MAX_U64_IN_USIZE;

/// Error produced by [U64USize::try_new]
#[derive(Debug, thiserror::Error)]
pub enum U64USizeConversionError<T: std::fmt::Debug> {
    /// Value can not be represented as u64
    #[error("Value can not be represented as a u64 value (max = {}): {:?}", u64::MAX, .0)]
    NoU64Repr(T),
    /// Value can not be represented as usize
    #[error("Value can not be represented as a usize value (max = {}): {:?}", usize::MAX, .0)]
    NoUSizeRepr(T),
    /// Value can not be represented as usize or u64
    #[error("Value can not be represented as a u64 (max = {}) or a usize (max = {}) value: {:?}", u64::MAX, usize::MAX, .0)]
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

    /// Checked addition. Computes `self + rhs`, returning [None] if the sum
    /// is not representable as both a u64 and a usize.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.u64()
            .checked_add(rhs.u64())
            .and_then(|v| Self::try_new(v).ok())
    }

    /// Checked subtraction. Computes `self - rhs`, returning [None] if the
    /// difference is not representable as both a u64 and a usize (i.e. if
    /// it would be negative).
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.u64()
            .checked_sub(rhs.u64())
            .and_then(|v| Self::try_new(v).ok())
    }
}

impl std::ops::Sub for U64USize {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        // Handling overflows EXACTLY as the normal numerics do.
        // I.e. in debug builds, we panic on overflow; in release builds
        // the u64 arithmetic wraps. The wrapped result is still range-checked
        // by new_or_panic, so on platforms where usize is narrower than u64
        // (e.g. 32 bit) a wrapped value above usize::MAX still panics.
        Self::new_or_panic(self.u64() - rhs.u64())
    }
}

impl std::ops::Add for U64USize {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        // Handling overflows EXACTLY as the normal numerics do.
        // I.e. in debug builds, we panic on overflow; in release builds
        // the u64 arithmetic wraps. The wrapped result is still range-checked
        // by new_or_panic, so on platforms where usize is narrower than u64
        // (e.g. 32 bit) a wrapped value above usize::MAX still panics.
        Self::new_or_panic(self.u64() + rhs.u64())
    }
}

/// Facilitates creation of [U64USize] in cases where truncation (clamping) into the
/// range of values representable as both a usize and a u64 is permissible
pub trait TruncateIntoU64USize {
    /// Check whether calling [TruncateIntoU64USize::truncate_to_u64usize] would truncate or return
    /// the value as-is
    fn fits_into_u64usize(&self) -> bool;

    /// Turn [Self] into a [U64USize]. If the value is representable as a usize and a u64, then
    /// the value will be returned as is. Otherwise the value is clamped into the representable
    /// range: Negative values become zero, values larger than the maximum representable value
    /// [MAX_U64_IN_USIZE] become [MAX_U64_IN_USIZE].
    ///
    /// Negative values are clamped to zero rather than the maximum representable value because
    /// a small negative number must not silently turn into the largest possible value; this
    /// type is used for sizes and offsets, where such a slip would be hazardous.
    fn truncate_to_u64usize(&self) -> U64USize;
}

/// Create instances of TruncateIntoU64USize
macro_rules! derive_TruncateIntoU64Usize {
    ($($T:ty),*) => {
        $(
            impl TruncateIntoU64USize for $T {
                fn fits_into_u64usize(&self) -> bool {
                    U64USize::try_new(*self).is_ok()
                }

                fn truncate_to_u64usize(&self) -> U64USize {
                    // Clamp negative source values to zero: A small negative
                    // number must not silently turn into the largest possible
                    // value.
                    //
                    // All supported source types except u128 convert into an i128
                    // without loss; the u128 conversion fails only for values beyond
                    // the i128 range, which saturate to the maximum below.
                    let as_i128: Result<i128, _> = (*self).try_into();
                    match as_i128 {
                        Ok(v) if v < 0 => U64USize::new_or_panic(0u8),
                        _ => U64USize::try_new(*self)
                            .unwrap_or(U64USize::new_or_panic(MAX_U64_IN_USIZE)),
                    }
                }
            }
        )*
    }
}

derive_TruncateIntoU64Usize!(
    U64USize, usize, isize, bool, u8, u16, u32, u64, u128, i8, i16, i32, i64, i128
);

/// Create instances of From for U64USize
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

/// Create instances of TryFrom for U64USize
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

/// Create instances of Into for U64USize
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

/// Create instances of TryInto for U64USize
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

#[cfg(test)]
mod tests {
    use super::*;

    fn v(n: u64) -> U64USize {
        U64USize::new_or_panic(n)
    }

    /// Addition and subtraction within the representable range behave like
    /// plain integer arithmetic
    #[test]
    fn add_sub_within_range() {
        assert_eq!(v(0) + v(0), v(0));
        assert_eq!(v(3) + v(4), v(7));
        assert_eq!(v(7) - v(4), v(3));
        assert_eq!(v(5) - v(5), v(0));
        assert_eq!(v(0) - v(0), v(0));

        assert_eq!(v(3).checked_add(v(4)), Some(v(7)));
        assert_eq!(v(7).checked_sub(v(4)), Some(v(3)));
        assert_eq!(v(5).checked_sub(v(5)), Some(v(0)));
    }

    /// `3 - 5` underflows and must return `None`; a wrapped result
    /// (`2**64 - 2`) fits into both a u64 and a 64-bit usize, so it must not
    /// be produced silently
    #[test]
    fn checked_sub_reports_underflow() {
        assert_eq!(v(3).checked_sub(v(5)), None);
        assert_eq!(v(0).checked_sub(v(1)), None);
    }

    /// `MAX + 1` exceeds the representable range and must return `None`
    /// (plain wrapping arithmetic would yield zero, an in-range value)
    #[test]
    fn checked_add_reports_overflow() {
        assert_eq!(v(MAX_U64_IN_USIZE).checked_add(v(1)), None);
        assert_eq!(v(MAX_U64_IN_USIZE).checked_add(v(MAX_U64_IN_USIZE)), None);
    }

    /// Negative values must clamp to zero, not saturate to the maximum
    /// representable value: A small negative number slipping through as the
    /// largest possible value is hazardous for a type used for sizes and
    /// offsets.
    #[test]
    fn truncate_negative_clamps_to_zero() {
        assert_eq!((-1i8).truncate_to_u64usize(), v(0));
        assert_eq!((-1i64).truncate_to_u64usize(), v(0));
        assert_eq!(i8::MIN.truncate_to_u64usize(), v(0));
        assert_eq!(isize::MIN.truncate_to_u64usize(), v(0));
        assert_eq!(i128::MIN.truncate_to_u64usize(), v(0));
        assert!(!(-1i8).fits_into_u64usize());
    }

    /// Small positive values pass through the truncating conversion unchanged
    #[test]
    fn truncate_positive_passthrough() {
        assert_eq!(0u8.truncate_to_u64usize(), v(0));
        assert_eq!(0i8.truncate_to_u64usize(), v(0));
        assert_eq!(1u8.truncate_to_u64usize(), v(1));
        assert_eq!(1337i32.truncate_to_u64usize(), v(1337));
        assert_eq!(1337usize.truncate_to_u64usize(), v(1337));
        assert!(42u8.fits_into_u64usize());
        assert!(42i8.fits_into_u64usize());
    }

    /// Values above the representable range saturate to the maximum
    /// representable value
    #[test]
    fn truncate_oversized_saturates_to_max() {
        assert_eq!(u64::MAX.truncate_to_u64usize(), v(MAX_U64_IN_USIZE));
        assert_eq!(u128::MAX.truncate_to_u64usize(), v(MAX_U64_IN_USIZE));
        assert_eq!(i128::MAX.truncate_to_u64usize(), v(MAX_U64_IN_USIZE));
        assert!(!u128::MAX.fits_into_u64usize());
        assert!(!i128::MAX.fits_into_u64usize());
    }
}
