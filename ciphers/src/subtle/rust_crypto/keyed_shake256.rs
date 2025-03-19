use anyhow::ensure;
use rosenpass_cipher_traits::primitives::{InferKeyedHash, KeyedHash};
use sha3::digest::{ExtendableOutput, Update, XofReader};
use sha3::Shake256;

pub use rosenpass_cipher_traits::algorithms::keyed_hash_shake256::{HASH_LEN, KEY_LEN};

/// An implementation of the [`KeyedHash`] trait backed by the RustCrypto implementation of SHAKE256.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SHAKE256Core<const KEY_LEN: usize, const HASH_LEN: usize>;

impl<const KEY_LEN: usize, const HASH_LEN: usize> KeyedHash<KEY_LEN, HASH_LEN>
    for SHAKE256Core<KEY_LEN, HASH_LEN>
{
    type Error = anyhow::Error;

    /// TODO: Rework test
    /// Provides a keyed hash function based on SHAKE256. To work for the protocol, the output length
    /// and key length are fixed to 32 bytes (also see [KEY_LEN] and [HASH_LEN]).
    ///
    /// Note that the SHAKE256 is designed for 64 bytes output length, which we truncate to 32 bytes
    /// to work well with the overall protocol. Referring to Table 4 of FIPS 202, this offers the
    /// same collision resistance as SHAKE128, but 256 bits of preimage resistance. We therefore
    /// prefer a truncated SHAKE256 over SHAKE128.
    ///
    /// TODO: Example/Test
    /// #Examples
    /// ```rust
    /// # use rosenpass_ciphers::subtle::rust_crypto::keyed_shake256::SHAKE256Core;
    /// use rosenpass_cipher_traits::primitives::KeyedHash;
    /// const KEY_LEN: usize = 32;
    /// const HASH_LEN: usize = 32;
    /// let key: [u8; 32] = [0; KEY_LEN];
    /// let data: [u8; 32] = [255; 32]; // arbitrary data, could also be longer
    /// // buffer for the hash output
    /// let mut hash_data: [u8; 32] = [0u8; HASH_LEN];
    ///
    /// assert!(SHAKE256Core::<32, 32>::keyed_hash(&key, &data, &mut hash_data).is_ok(), "Hashing has to return OK result");
    /// # let expected_hash: &[u8] = &[174, 4, 47, 188, 1, 228, 179, 246, 67, 43, 255, 94, 155, 11,
    /// 187, 161, 38, 110, 217, 23, 4, 62, 172, 30, 218, 187, 249, 80, 171, 21, 145, 238];
    /// # assert_eq!(hash_data, expected_hash);
    /// ```
    fn keyed_hash(
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        // Since SHAKE256 is a XOF, we fix the output length manually to what is required for the
        // protocol.
        ensure!(out.len() == HASH_LEN);
        // Not bothering with padding; the implementation
        // uses appropriately sized keys.
        ensure!(key.len() == KEY_LEN);
        let mut shake256 = Shake256::default();
        shake256.update(key);
        shake256.update(data);

        // Since we use domain separation extensively, related outputs of the truncated XOF
        // are not a concern. This follows the NIST recommendations in Section A.2 of the FIPS 202
        // standard, (pages 24/25, i.e., 32/33 in the PDF).
        shake256.finalize_xof().read(out);
        Ok(())
    }
}

impl<const KEY_LEN: usize, const HASH_LEN: usize> SHAKE256Core<KEY_LEN, HASH_LEN> {
    pub fn new() -> Self {
        Self
    }
}

impl<const KEY_LEN: usize, const HASH_LEN: usize> Default for SHAKE256Core<KEY_LEN, HASH_LEN> {
    fn default() -> Self {
        Self::new()
    }
}

/// TODO use inferred hash somehow here
/// ```rust
/// # use rosenpass_ciphers::subtle::rust_crypto::keyed_shake256::{SHAKE256};
/// use rosenpass_cipher_traits::primitives::KeyedHashInstance;
/// const KEY_LEN: usize = 32;
/// const HASH_LEN: usize = 32;
/// let key: [u8; KEY_LEN] = [0; KEY_LEN];
/// let data: [u8; 32] = [255; 32]; // arbitrary data, could also be longer
/// // buffer for the hash output
/// let mut hash_data: [u8; 32] = [0u8; HASH_LEN];
/// // TODO: Note that we are using inferred hash here
/// assert!(SHAKE256::new().keyed_hash(&key, &data, &mut hash_data).is_ok(), "Hashing has to return OK result");
/// # let expected_hash: &[u8] = &[174, 4, 47, 188, 1, 228, 179, 246, 67, 43, 255, 94, 155, 11, 187,
/// 161, 38, 110, 217, 23, 4, 62, 172, 30, 218, 187, 249, 80, 171, 21, 145, 238];
/// # assert_eq!(hash_data, expected_hash);
/// ```
pub type SHAKE256<const KEY_LEN: usize, const HASH_LEN: usize> =
    InferKeyedHash<SHAKE256Core<KEY_LEN, HASH_LEN>, KEY_LEN, HASH_LEN>;

/// TODO: Documentation and more interesting test
/// ```rust
/// # use rosenpass_ciphers::subtle::keyed_shake256::{SHAKE256_32};
/// use rosenpass_cipher_traits::primitives::KeyedHashInstance;
/// const KEY_LEN: usize = 32;
/// const HASH_LEN: usize = 32;
/// let key: [u8; 32] = [0; KEY_LEN];
/// let data: [u8; 32] = [255; 32]; // arbitrary data, could also be longer
/// // buffer for the hash output
/// let mut hash_data: [u8; 32] = [0u8; HASH_LEN];
///
/// assert!(SHAKE256_32::new().keyed_hash(&key, &data, &mut hash_data).is_ok(), "Hashing has to return OK result");
/// # let expected_hash: &[u8] = &[174, 4, 47, 188, 1, 228, 179, 246, 67, 43, 255, 94, 155, 11, 187,
/// 161, 38, 110, 217, 23, 4, 62, 172, 30, 218, 187, 249, 80, 171, 21, 145, 238];
/// # assert_eq!(hash_data, expected_hash);
/// ```
pub type SHAKE256_32 = SHAKE256<32, 32>;
