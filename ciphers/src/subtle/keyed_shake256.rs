use anyhow::ensure;
use rosenpass_to::ops::copy_slice;
use rosenpass_to::{with_destination, To};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;
use zeroize::Zeroizing;

/// The key length, 32 bytes or 256 bits.
pub const KEY_LEN: usize = 32;
/// The output length, 32 bytes or 256 bits.
pub const OUT_LEN: usize = 32;
/// The minimal key length, identical to [KEY_LEN].
pub const KEY_MIN: usize = KEY_LEN;
/// The maximal key length, identical to [KEY_LEN].
pub const KEY_MAX: usize = KEY_LEN;
/// The minimal output length.
pub const OUT_MIN: usize = OUT_LEN;
/// The maximal output length.
pub const OUT_MAX: usize = OUT_LEN;

/// Provides a keyed hash function based on SHAKE256. To work for the protocol, the output length
/// and key length are fixed to 32 bytes (also see [KEY_LEN] and [OUT_LEN]).
///
/// Note that the SHAKE256 is designed for 64 bytes output length, which we truncate to 32 bytes
/// to work well with the overall protocol. Referring to Table 4 of FIPS 202, this offers the
/// same collision resistance as SHAKE128, but 256 bits of preimage resistance. We therefore
/// prefer a truncated SHAKE256 over SHAKE128.
///
/// #Examples
/// ```rust
/// # use rosenpass_ciphers::subtle::keyed_shake256::hash;
/// use rosenpass_to::To;
/// let key: [u8; 32] = [0; 32];
/// let data: [u8; 32] = [255; 32];
/// // buffer for the hash output
/// let mut hash_data: [u8; 32] = [0u8; 32];
///
/// assert!(hash(&key, &data).to(&mut hash_data).is_ok(), "Hashing has to return OK result");
/// # let expected_hash: &[u8] = &[166, 35, 212, 217, 225, 226, 193, 131, 163, 196, 223, 79, 56,
/// 193, 107, 23, 45, 213, 14, 86, 198, 177, 49, 182, 233, 217, 157, 39, 188, 240, 140, 163];
/// # assert_eq!(hash_data, expected_hash);
/// ```
pub fn hash<'a>(key: &'a [u8], data: &'a [u8]) -> impl To<[u8], anyhow::Result<()>> + 'a {
    with_destination(|out: &mut [u8]| {
        // Since SHAKE256 is a XOF, we fix the output length manually to what is required for the
        // protocol.
        ensure!(out.len() == OUT_LEN);
        let mut out: [u8; OUT_LEN] = out.try_into().unwrap();
        // Not bothering with padding; the implementation
        // uses appropriately sized keys.
        ensure!(key.len() == KEY_LEN);
        let mut shake256 = Shake256::default();
        shake256.update(key);
        shake256.update(data);

        // Following the NIST recommendations in Section A.2 of the FIPS 202 standard,
        // (pages 24/25, i.e., 32/33 in the PDF) we append the length of the input to the end of
        // the input. This prevents that if the same input is used with two different output lengths,
        // the shorter output is a prefix of the longer output. See the Section A.2 of the FIPS 202
        // standard for more details.
        shake256.update(&((OUT_LEN as u8).to_le_bytes()));
        shake256.finalize_xof().read(&mut out);
        Ok(())
    })
}
