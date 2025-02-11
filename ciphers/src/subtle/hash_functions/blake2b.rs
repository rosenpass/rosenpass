use zeroize::Zeroizing;

use blake2::digest::crypto_common::generic_array::GenericArray;
use blake2::digest::crypto_common::typenum::U32;
use blake2::digest::crypto_common::KeySizeUser;
use blake2::digest::{FixedOutput, Mac, OutputSizeUser};
use blake2::Blake2bMac;

use rosenpass_to::{ops::copy_slice, with_destination, To};
use rosenpass_util::typenum2const;

/// Specify that the used implementation of BLAKE2b is the MAC version of BLAKE2b
/// with output and key length of 32 bytes (see [Blake2bMac]).
type Impl = Blake2bMac<U32>;

type KeyLen = <Impl as KeySizeUser>::KeySize;
type OutLen = <Impl as OutputSizeUser>::OutputSize;

/// The key length for BLAKE2b supported by this API. Currently 32 Bytes.
const KEY_LEN: usize = typenum2const! { KeyLen };
/// The output length for BLAKE2b supported by this API. Currently 32 Bytes.
const OUT_LEN: usize = typenum2const! { OutLen };

/// Minimal key length supported by this API.
pub const KEY_MIN: usize = KEY_LEN;
/// maximal key length supported by this API.
pub const KEY_MAX: usize = KEY_LEN;
/// minimal output length supported by this API.
pub const OUT_MIN: usize = OUT_LEN;
/// maximal output length supported by this API.
pub const OUT_MAX: usize = OUT_LEN;

/// Hashes the given `data` with the [Blake2bMac] hash function under the given `key`.
/// The both the length of the output the length of the key 32 bytes (or 256 bits).  
///
/// TODO: Adapt example
/// # Examples
///
///```rust
/// # use rosenpass_ciphers::subtle::blake2b::hash;
/// use rosenpass_to::To;
/// let zero_key: [u8; 32] = [0; 32];
/// let data: [u8; 32] = [255; 32];
/// // buffer for the hash output
/// let mut hash_data: [u8; 32] = [0u8; 32];  
///
/// assert!(hash(&zero_key, &data).to(&mut hash_data).is_ok(), "Hashing has to return OK result");
///```
///
#[inline]
pub fn hash<'a>(key: &'a [u8], data: &'a [u8]) -> impl To<[u8], anyhow::Result<()>> + 'a {
    with_destination(|out: &mut [u8]| {
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
    })
}
