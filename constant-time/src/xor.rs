//! xor

use core::hint::black_box;
use rosenpass_to::{with_destination, To};

/// Xors the source into the destination
///
/// # Panics
/// If source and destination are of different sizes.
///
/// # Leaks
/// TODO: mention here if this function leaks any information, see
/// <https://github.com/rosenpass/rosenpass/issues/232>
///
/// ## Tests
/// For discussion on how to ensure the constant-time execution of this function, see
/// <https://github.com/rosenpass/rosenpass/issues/232>
///
/// # Examples
///
/// ```
/// use rosenpass_constant_time::xor;
/// use rosenpass_to::To;
/// assert_eq!(
///     xor(b"world").to_this(|| b"hello".to_vec()),
///     b"\x1f\n\x1e\x00\x0b");
/// ```
#[inline]
pub fn xor(src: &[u8]) -> impl To<[u8], ()> + '_ {
    with_destination(|dst: &mut [u8]| {
        assert!(black_box(src.len()) == black_box(dst.len()));
        for (dv, sv) in dst.iter_mut().zip(src.iter()) {
            *black_box(dv) ^= black_box(*sv);
        }
    })
}
