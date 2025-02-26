use zeroize::Zeroizing;

use blake2::digest::crypto_common::generic_array::GenericArray;
use blake2::digest::crypto_common::typenum::U32;
use blake2::digest::{FixedOutput, Mac};
use blake2::Blake2bMac;

use rosenpass_cipher_traits::primitives::KeyedHash;
use rosenpass_to::{ops::copy_slice, To};

/// Specify that the used implementation of BLAKE2b is the MAC version of BLAKE2b
/// with output and key length of 32 bytes (see [Blake2bMac]).
type Impl = Blake2bMac<U32>;

/// The key length for BLAKE2b supported by this API. Currently 32 Bytes.
const KEY_LEN: usize = 32;
/// The output length for BLAKE2b supported by this API. Currently 32 Bytes.
const OUT_LEN: usize = 32;

/// Hashes the given `data` with the [Blake2bMac] hash function under the given `key`.
/// The both the length of the output the length of the key 32 bytes (or 256 bits).  
pub struct Blake2b;

impl KeyedHash<KEY_LEN, OUT_LEN> for Blake2b {
    type Error = anyhow::Error;

    fn keyed_hash(
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; OUT_LEN],
    ) -> Result<(), Self::Error> {
        let mut h = Impl::new_from_slice(key)?;
        h.update(data);

        // Jesus christ, blake2 crate, your usage of GenericArray might be nice and fancy,
        // but it introduces a ton of complexity. This cost me half an hour just to figure
        // out the right way to use the imports while allowing for zeroization.
        // An API based on slices might actually be simpler.
        let mut tmp = Zeroizing::new([0u8; OUT_LEN]);
        let tmp = GenericArray::from_mut_slice(tmp.as_mut());
        h.finalize_into(tmp);
        copy_slice(tmp.as_ref()).to(out);
        Ok(())
    }
}

impl rosenpass_cipher_traits::algorithms::KeyedHashBlake2b for Blake2b {}
