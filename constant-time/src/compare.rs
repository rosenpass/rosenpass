use core::ptr;

/// Little endian memcmp version of quinier/memsec
/// https://github.com/quininer/memsec/blob/bbc647967ff6d20d6dccf1c85f5d9037fcadd3b0/src/lib.rs#L30
#[inline(never)]
pub unsafe fn memcmp_le(b1: *const u8, b2: *const u8, len: usize) -> i32 {
    let mut res = 0;
    for i in 0..len {
        let diff =
            i32::from(ptr::read_volatile(b1.add(i))) - i32::from(ptr::read_volatile(b2.add(i)));
        res = (res & (((diff - 1) & !diff) >> 8)) | diff;
    }
    ((res - 1) >> 8) + (res >> 8) + 1
}

/// compares two slices of memory content and returns an integer indicating the relationship between
/// the slices
///
/// ## Returns
/// - <0 if the first byte that does not match both slices has a lower value in `a` than in `b`
/// - 0 if the contents are equal
/// - >0 if the first byte that does not match both slices has a higher value in `a` than in `b`
///
/// ## Leaks
/// If the two slices have differents lengths, the function will return immediately. This
/// effectively leaks the information whether the slices have equal length or not. This is widely
/// considered safe.
///
/// The execution time of the function grows approx. linear with the length of the input. This is
/// considered safe.
///
/// ## Tests
/// For discussion on how to ensure the constant-time execution of this function, see
/// <https://github.com/rosenpass/rosenpass/issues/232>
#[inline]
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    assert!(a.len() == b.len());
    unsafe { memcmp_le(a.as_ptr(), b.as_ptr(), a.len()) }
}
