use core::hint::black_box;

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
        assert!(black_box(src.len()) == black_box(dst.len()));
        for (dv, sv) in dst.iter_mut().zip(src.iter()) {
            *black_box(dv) ^= black_box(*sv);
        }
    })
}

#[inline]
pub fn memcmp(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len()
        && unsafe {
            memsec::memeq(
                a.as_ptr() as *const u8,
                b.as_ptr() as *const u8,
                a.len(),
            )
        }
}

#[inline]
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    assert!(a.len() == b.len());
    unsafe { memsec::memcmp(a.as_ptr(), b.as_ptr(), a.len()) }
}

/// Interpret the given slice as a little-endian unsigned integer
/// and increment that integer.
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
