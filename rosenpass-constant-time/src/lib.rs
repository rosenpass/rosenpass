/// Xors a and b element-wise and writes the result into a.
///
/// # Examples
///
/// ```
/// use rosenpass_constant_time::xor_into;
/// let mut a = String::from("hello").into_bytes();
/// let b = b"world";
/// xor_into(&mut a, b);
/// assert_eq!(&a, b"\x1f\n\x1e\x00\x0b");
/// ```
#[inline]
pub fn xor_into(a: &mut [u8], b: &[u8]) {
    assert!(a.len() == b.len());
    for (av, bv) in a.iter_mut().zip(b.iter()) {
        *av ^= *bv;
    }
}
