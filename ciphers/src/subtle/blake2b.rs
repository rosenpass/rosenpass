use rosenpass_cipher_traits::{KeyedHash, KeyedHashError as Error};

use crate::Provider;

use rosenpass_to::{with_destination, To};

// NOTE: typenum2const gives 64 for KeyLen. This didn't ahve an effect before, because that value
// wasn't really used, but we use it now.

/// The key length for BLAKE2b supported by this API. Currently 32 Bytes.
const KEY_LEN: usize = 32;
/// The output length for BLAKE2b supported by this API. Currently 32 Bytes.
const OUT_LEN: usize = 32;

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
pub fn hash<'a>(
    key: &'a [u8; KEY_LEN],
    data: &'a [u8],
) -> impl To<[u8; OUT_LEN], Result<(), Error>> + 'a {
    with_destination(|out: &mut [u8; OUT_LEN]| {
        <Provider as rosenpass_cipher_traits::Provider>::KeyedBlake2b::keyed_hash(key, data, out)
    })
}
