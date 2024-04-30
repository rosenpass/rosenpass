use core::hint::black_box;

/// Interpret the given slice as a little-endian unsigned integer
/// and increment that integer.
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
