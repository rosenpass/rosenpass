//! Making sure size representations fit both into [usize] and [u64]

use static_assertions::const_assert;

mod constants;
pub use constants::*;

#[allow(clippy::module_inception)]
mod u64uint;
pub use u64uint::*;

mod range;
pub use range::*;

/// Safe conversion from usize to u64
///
/// TODO: Deprecate this
pub const fn usize_to_u64(v: usize) -> u64 {
    const_assert!(u64::BITS >= usize::BITS);
    v as u64
}
