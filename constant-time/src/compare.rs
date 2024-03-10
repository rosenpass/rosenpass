/// Compares two slices of memory containing arbitrary-length little endian unsigned integers
/// and returns an integer indicating the relationship between the slices.
///
/// ## Returns
///
/// - -1 if a < b
/// - 0 if a = b
/// - 1 if a > b
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
///
/// ```rust
/// use rosenpass_constant_time::compare;
/// assert_eq!(compare(&[], &[]),    0);
///
/// assert_eq!(compare(&[0], &[1]), -1);
/// assert_eq!(compare(&[0], &[0]), 0);
/// assert_eq!(compare(&[1], &[0]), 1);
///
/// assert_eq!(compare(&[0, 0], &[1, 0]), -1);
/// assert_eq!(compare(&[0, 0], &[0, 0]), 0);
/// assert_eq!(compare(&[1, 0], &[0, 0]), 1);
///
/// assert_eq!(compare(&[1, 0], &[0, 1]), -1);
/// assert_eq!(compare(&[0, 1], &[0, 0]), 1);
/// ```
///
/// For discussion on how to ensure the constant-time execution of this function, see
/// <https://github.com/rosenpass/rosenpass/issues/232>
#[inline]
pub fn compare(a: &[u8], b: &[u8]) -> i32 {
    assert!(a.len() == b.len());
    unsafe { memsec::memcmp(a.as_ptr(), b.as_ptr(), a.len()) }
}
