use std::result::Result;
use digest::{Update, XofReader};
use crate::util::types::Leftright;
use crate::util::io::{WriteSecret, CountAndWriteSecret};

#[cfg(test)]
use crate::util::io::assemble_secret;

/// Variable length encoding for unsigned numbers as specified by in
/// NIST Special Publication 800-185.
///
/// This corresponds to left_encode(…) if `lr == Leftright::Left`
/// and to right_encode(…) if `lr == Leftright::Right`.
///
/// # Panics
///
/// This will panic if the number `v` is greater than $2^{2040}-1$,
/// i.e. if more than 255 bits are required to represent the number.
///
/// For the natively supported integers (u8…u128 and usize), this will not panic
/// unless usize is an u256 now.
///
/// # Example
/// 
/// ```
/// use crate::util::types::Leftright::*;
///
/// assert_eq!(assemble_secret(|w| leftright_encode(Left, w, 0)), assemble_secret(|w| left_encode(w, 0)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Left, w, 1)), assemble_secret(|w| left_encode(w, 1)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Left, w, 0xff)), assemble_secret(|w| left_encode(w, 0xff)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Left, w, 0x100)), assemble_secret(|w| left_encode(w, 0x100)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Left, w, 0x010203)), assemble_secret(|w| left_encode(w, 0x010203)));
///
/// assert_eq!(assemble_secret(|w| leftright_encode(Right, w, 0)), assemble_secret(|w| right_encode(w, 0)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Right, w, 1)), assemble_secret(|w| right_encode(w, 1)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Right, w, 0xff)), assemble_secret(|w| right_encode(w, 0xff)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Right, w, 0x100)), assemble_secret(|w| right_encode(w, 0x100)));
/// assert_eq!(assemble_secret(|w| leftright_encode(Right, w, 0x010203)), assemble_secret(|w| right_encode(w, 0x010203)));
/// ```
pub(crate) fn leftright_encode<W, N>(lr: Leftright, dst: W, v: &N)
        -> Result<(), W::Error>
    where
        W: WriteSecret, 
        N: ToBytes {
    use Leftright::*;
    let be = v.to_be_bytes();
    let trailing_zeros = be.rev().take_while(|v| v == 0).count();
    let num_bytes = std::max(1, be.len() - trailing_zeros);
    assert!(num_bytes < 256);
    match lr {
        Left => {
            dst.write(from_ref(num_bytes.into()))?;
            dst.write(&be[..num_bytes])?;
        },
        Right => {
            dst.write(&be[..num_bytes])?;
            dst.write(from_ref(num_bytes.into()))?;
        }
    }
    Ok(())
}

/// Variable length encoding for unsigned numbers as specified by in
/// NIST Special Publication 800-185.
/// 
/// First writes a single byte indication the width of the
/// encoded number to `dst` then writes the number in big-endian
/// format.
///
/// # Panics
///
/// This will panic if the number `v` is greater than $2^{2040}-1$,
/// i.e. if more than 255 bits are required to represent the number.
///
/// For the natively supported integers (u8…u128 and usize), this will not panic
/// unless usize is an u256 now.
///
/// # Example
/// 
/// ```
/// assert_eq!(assemble_secret(|w| left_encode(w, 0)), b"\1\0");
/// assert_eq!(assemble_secret(|w| left_encode(w, 1)), b"\1\1");
/// assert_eq!(assemble_secret(|w| left_encode(w, 0xff)), b"\1\0xff");
/// assert_eq!(assemble_secret(|w| left_encode(w, 0x100)), b"\1\0\1");
/// assert_eq!(assemble_secret(|w| left_encode(w, 0x010203)), b"\3\1\2\3");
/// ```
pub(crate) fn left_encode<W, N>(dst: W, v: &N)
        -> Result<(), W::Error>
    where
        W: Write, 
        N: ToBytes {
    nist_leftright_encode(Leftright::Left, dst, v)
}

/// Variable length encoding for unsigned numbers as specified by in
/// NIST Special Publication 800-185.
///
/// This uses the same format as `left_encode` but swaps length tag
/// and then length of the number itself.
///
/// # Panics
///
/// This will panic if the number `v` is greater than $2^{2040}-1$,
/// i.e. if more than 255 bits are required to represent the number.
///
/// For the natively supported integers (u8…u128 and usize), this will not panic
/// unless usize is an u256 now.
///
/// # Example
/// 
/// ```
/// assert_eq!(assemble_secret(|w| left_encode(w, 0)), b"\0\1");
/// assert_eq!(assemble_secret(|w| left_encode(w, 1)), b"\1\1");
/// assert_eq!(assemble_secret(|w| left_encode(w, 0xff)), b"\0xff\1");
/// assert_eq!(assemble_secret(|w| left_encode(w, 0x100)), b"\0\1\1");
/// assert_eq!(assemble_secret(|w| left_encode(w, 0x010203)), b"\1\2\3\3");
/// ```
pub(crate) fn right_encode<W, N>(dst: &mut W, v: &N)
        -> Result<(), W::Error>
    where
        W: WriteSecret, 
        N: ToBytes {
    nist_leftright_encode(Leftright::Right, dst, v)
}

/// Serialization for variable length strings as specified by in
/// NIST Special Publication 800-185.
///
/// This first writes the length of the string using `left_encode` to `dst`
/// then copies the string itself to `dst`.
/// 
/// # Example
/// 
/// ```
/// assert_eq!(assemble_secret(|w| encode_string(w, b"")), b"\1\0");
/// assert_eq!(assemble_secret(|w| encode_string(w, b"\0")), b"\1\1\0");
/// assert_eq!(assemble_secret(|w| encode_string(w, b"Hello")), b"\1\5Hello");
/// assert_eq!(assemble_secret(|w| encode_string(w, b"Hello World")), b"\1\x0AHello World");
/// ```
pub(crate) pub fn encode_string<W>(dst: W, str: &[u8])
        -> Result<(), W::Error>
    where
        W: WriteSecret {
    /// This will not panic unless `usize` is an u256 now.
    left_encode(&mut dst, str.len())?;
    w.write_all(str)?;
    Ok(())
}

/// Serialize arbitrary data and then pad the output using zero bytes
/// as specified NIST Special Publication 800-185.
///
/// This first writes the width of the padding unit `pad_to` to `dst`
/// and then calls `f` to serialize arbitrary data. Finally, this function
/// writes null bytes until the total number of bytes written is a multiple
/// of `pad_to`.
///
/// # Example
/// 
/// ```
/// assert_eq!(assemble_secret(|w| bytepad(w, 5, |w| )), b"\1\5\0\0\0");
/// assert_eq!(assemble_secret(|w| bytepad(w, 5, |w| w.write_all(b"Hello"))), b"\1\5Hello\0\0\0");
/// assert_eq!(assemble_secret(|w| bytepad(w, 5, |w| w.write_all(b"Hello dearie!"))), b"\1\5Hello dearie!");
/// assert_eq!(assemble_secret(|w| bytepad(w, 5, |w| w.write_all(b"_"))), b"\1\5_\0\0");
/// ```
pub(crate) fn bytepad<W, Fn>(dst: W, pad_to: u64, f: Fn)
        -> Result<(), W::Error>
    where
        W: WriteSecret,
        Fn: FnOnce<CountAndWrite> {
    let w = CountAndWrite::new(dst);
    nist_left_encode(&mut w, pad_to)?;
    f(w)?;
    for _ in ..ceiling_remainder(w2.get_count(), pad_to) {
        w.write_all(from_ref(0u8.into()))?;
    }
    Ok(())
}

///
#[inline]
pub(crate) fn kmac256(out: &mut [u8], key: &[u8], data: &[u8]) {
    // A proper implementation of KMAC is currently not available in the sha3 crate, but they do
    // provide cSHAKE which can be used to implement KMAC
    //
    // Issue:
    //   https://github.com/RustCrypto/MACs/issues/133
    //   "kmac: Towards an implementation"
    //
    // KMAC Spec:
    //   https://doi.org/10.6028/NIST.SP.800-185
    //   "SHA-3 derived functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
    //   Page 10
    use sha3::{CShake256, CShake356Core};

    let hasher = CShake256::from_core(
        CShake356Core::new_with_function_name(&"", &"KMAC"));

    bytepad(hasher, 168, |w| encode_string(w, key)).guaranteed();
    hasher.update(data);
    right_encode(hasher, out.len()).guaranteed();

    hasher.finalize_xof_into(out);
}
