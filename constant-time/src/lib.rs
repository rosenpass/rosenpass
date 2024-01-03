use rosenpass_to::{with_destination, To};

/// Xors the source into the destination
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
///
/// # Panics
///
/// If source and destination are of different sizes.
#[inline]
pub fn xor(src: &[u8]) -> impl To<[u8], ()> + '_ {
    with_destination(|dst: &mut [u8]| {
        assert!(src.len() == dst.len());
        for (dv, sv) in dst.iter_mut().zip(src.iter()) {
            *dv ^= *sv;
        }
    })
}
