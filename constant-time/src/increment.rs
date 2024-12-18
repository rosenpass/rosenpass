//! Incrementing numbers

use core::hint::black_box;

/// Interpret the given slice as a little-endian unsigned integer
/// and increment that integer.
///
/// # Leaks
/// This function may leak timing information in the following ways:
///
/// - The function execution time is linearly proportional to the input length
/// - The number of carry operations that occur may affect timing slightly
/// - Memory access patterns are sequential and predictable
///
/// The carry operation timing variation is mitigated through the use of black_box,
/// but the linear scaling with input size is inherent to the operation.
/// These timing characteristics are generally considered acceptable for most
/// cryptographic counter implementations.
///
/// ## Tests
/// For discussion on how to ensure the constant-time execution of this function, see
/// <https://github.com/rosenpass/rosenpass/issues/232>
///
/// # Examples
///
/// ```
/// use rosenpass_constant_time::increment as inc;
/// use rosenpass_to::To;
///
/// fn testcase(v: &[u8], correct: &[u8]) {
///   let mut v = v.to_owned();
///   inc(&mut v);
///   assert_eq!(&v, correct);
/// }
///
/// testcase(b"", b"");
/// testcase(b"\x00", b"\x01");
/// testcase(b"\x01", b"\x02");
/// testcase(b"\xfe", b"\xff");
/// testcase(b"\xff", b"\x00");
/// testcase(b"\x00\x00", b"\x01\x00");
/// testcase(b"\x01\x00", b"\x02\x00");
/// testcase(b"\xfe\x00", b"\xff\x00");
/// testcase(b"\xff\x00", b"\x00\x01");
/// testcase(b"\x00\x00\x00\x00\x00\x00", b"\x01\x00\x00\x00\x00\x00");
/// testcase(b"\x00\xa3\x00\x77\x00\x00", b"\x01\xa3\x00\x77\x00\x00");
/// testcase(b"\xff\xa3\x00\x77\x00\x00", b"\x00\xa4\x00\x77\x00\x00");
/// testcase(b"\xff\xff\xff\x77\x00\x00", b"\x00\x00\x00\x78\x00\x00");
/// ```
#[inline]
pub fn increment(v: &mut [u8]) {
    let mut carry = 1u8;
    for val in v.iter_mut() {
        let (v, c) = black_box(*val).overflowing_add(black_box(carry));
        *black_box(val) = v;
        *black_box(&mut carry) = black_box(black_box(c) as u8);
    }
}
