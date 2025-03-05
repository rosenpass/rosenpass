use rosenpass_cipher_traits::{
    algorithms::KeyedHashIncorrectHmacBlake2b,
    primitives::{InferKeyedHash, KeyedHash, KeyedHashTo},
};
use rosenpass_constant_time::xor;
use rosenpass_to::{ops::copy_slice, To};
use zeroize::Zeroizing;

#[cfg(not(feature = "experiment_libcrux_blake2"))]
use crate::subtle::rust_crypto::blake2b::Blake2b;
#[cfg(not(feature = "experiment_libcrux_blake2"))]
use anyhow::Error;

#[cfg(feature = "experiment_libcrux_blake2")]
use crate::subtle::libcrux::blake2b::{Blake2b, Error};

/// The key length, 32 bytes or 256 bits.
pub const KEY_LEN: usize = 32;

/// The hash length, 32 bytes or 256 bits.
pub const HASH_LEN: usize = 32;

/// This is a woefully incorrect implementation of hmac_blake2b.
/// See <https://github.com/rosenpass/rosenpass/issues/68#issuecomment-1563612222>
///
/// It accepts 32 byte keys, exclusively.
///
/// This will be replaced, likely by Kekkac at some point soon.
/// <https://github.com/rosenpass/rosenpass/pull/145>
///
/// # Examples
///```rust
/// # use rosenpass_ciphers::subtle::custom::incorrect_hmac_blake2b::IncorrectHmacBlake2bCore;
/// use rosenpass_cipher_traits::primitives::KeyedHashTo;
/// use rosenpass_to::To;
/// let key: [u8; 32] = [0; 32];
/// let data: [u8; 32] = [255; 32];
/// // buffer for the hash output
/// let mut hash_data: [u8; 32] = [0u8; 32];
///
/// assert!(IncorrectHmacBlake2bCore::keyed_hash_to(&key, &data).to(&mut hash_data).is_ok(), "Hashing has to return OK result");
/// # let expected_hash: &[u8] = &[5, 152, 135, 141, 151, 106, 147, 8, 220, 95, 38, 66, 29, 33, 3,
/// 104, 250, 114, 131, 119, 27, 56, 59, 44, 11, 67, 230, 113, 112, 20, 80, 103];
/// # assert_eq!(hash_data, expected_hash);
///```
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncorrectHmacBlake2bCore;

impl KeyedHash<KEY_LEN, HASH_LEN> for IncorrectHmacBlake2bCore {
    type Error = Error;

    fn keyed_hash(
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        const IPAD: [u8; KEY_LEN] = [0x36u8; KEY_LEN];
        const OPAD: [u8; KEY_LEN] = [0x5Cu8; KEY_LEN];

        type Key = Zeroizing<[u8; KEY_LEN]>;
        let mut tmp_key = Key::default();

        copy_slice(key).to(tmp_key.as_mut());
        xor(&IPAD).to(tmp_key.as_mut());
        let mut outer_data = Key::default();
        Blake2b::keyed_hash_to(&tmp_key, data).to(&mut outer_data)?;

        copy_slice(key).to(tmp_key.as_mut());
        xor(&OPAD).to(tmp_key.as_mut());
        Blake2b::keyed_hash_to(&tmp_key, outer_data.as_ref()).to(out)?;

        Ok(())
    }
}

pub type IncorrectHmacBlake2b = InferKeyedHash<IncorrectHmacBlake2bCore, KEY_LEN, HASH_LEN>;

impl KeyedHashIncorrectHmacBlake2b for IncorrectHmacBlake2bCore {}
