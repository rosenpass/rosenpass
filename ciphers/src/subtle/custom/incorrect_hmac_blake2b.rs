use anyhow::ensure;
use rosenpass_cipher_traits::keyed_hash::{InferKeyedHash, KeyedHash};
use rosenpass_constant_time::xor;
use rosenpass_to::{ops::copy_slice, To};
use zeroize::Zeroizing;

use crate::subtle::rust_crypto::blake2b;

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
/// # use rosenpass_ciphers::subtle::incorrect_hmac_blake2b::hash;
/// use rosenpass_to::To;
/// let key: [u8; 32] = [0; 32];
/// let data: [u8; 32] = [255; 32];
/// // buffer for the hash output
/// let mut hash_data: [u8; 32] = [0u8; 32];
///
/// assert!(hash(&key, &data).to(&mut hash_data).is_ok(), "Hashing has to return OK result");
/// # let expected_hash: &[u8] = &[5, 152, 135, 141, 151, 106, 147, 8, 220, 95, 38, 66, 29, 33, 3,
/// 104, 250, 114, 131, 119, 27, 56, 59, 44, 11, 67, 230, 113, 112, 20, 80, 103];
/// # assert_eq!(hash_data, expected_hash);
///```
///
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IncorrectHmacBlake2bCore;

impl KeyedHash<KEY_LEN, HASH_LEN> for IncorrectHmacBlake2bCore {
    type Error = anyhow::Error;

    fn keyed_hash(
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        const IPAD: [u8; KEY_LEN] = [0x36u8; KEY_LEN];
        const OPAD: [u8; KEY_LEN] = [0x5Cu8; KEY_LEN];

        // Not bothering with padding; the implementation
        // uses appropriately sized keys.
        ensure!(key.len() == KEY_LEN);

        type Key = Zeroizing<[u8; KEY_LEN]>;
        let mut tmp_key = Key::default();

        copy_slice(key).to(tmp_key.as_mut());
        xor(&IPAD).to(tmp_key.as_mut());
        let mut outer_data = Key::default();
        blake2b::hash(tmp_key.as_ref(), data).to(outer_data.as_mut())?;

        copy_slice(key).to(tmp_key.as_mut());
        xor(&OPAD).to(tmp_key.as_mut());
        blake2b::hash(tmp_key.as_ref(), outer_data.as_ref()).to(out)?;

        Ok(())
    }
}

pub type IncorrectHmacBlake2b = InferKeyedHash<IncorrectHmacBlake2bCore, KEY_LEN, HASH_LEN>;
