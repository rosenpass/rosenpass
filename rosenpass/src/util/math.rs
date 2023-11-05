use core::ops::{Rem, Add, Sub};

/// Round lhs up to the next multiple of div
///
/// # Examples
///
/// ```
/// assert_eq!(round_up(10u8, 5u8), 10u8);
/// assert_eq!(round_up(.3f32, .2f32), .4f32);
/// assert_eq!(round_up(22u64, 17u64), 32u64);
/// ```
pub(crate) fn round_up<T>(lhs: T, div: T) -> T
    where
        T: Rem + Add {
    lhs + (lhs % div)
}

/// Calculates the difference between val and the next highest multiple of div
///
/// # Examples
///
/// ```
/// assert_eq!(round_up(10u8, 5u8), 0u8);
/// assert_eq!(round_up(.3f32, .2f32), .1f32);
/// assert_eq!(round_up(22u64, 17u64), 32u64);
/// ```
pub(crate) fn gap_towards_multiple<T>(val: T, div: T)
    where
        T: Rem + Add + Sub {
    round_up(val, div) - val
}
