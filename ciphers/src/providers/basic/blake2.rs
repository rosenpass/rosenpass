use rosenpass_cipher_traits::{KeyedHash, KeyedHashBlake2b, KeyedHashError as Error};
use zeroize::Zeroizing;

use blake2::digest::crypto_common::generic_array::GenericArray;
use blake2::digest::crypto_common::typenum::U32;
use blake2::digest::{FixedOutput, Mac};
use blake2::Blake2bMac;

use rosenpass_to::{ops::copy_slice, To};

type Impl = Blake2bMac<U32>;

pub const KEY_LEN: usize = 32;
pub const OUT_LEN: usize = 32;

#[derive(Clone, Copy, Default)]
pub struct KeyedBlake2b;

impl KeyedHash<KEY_LEN, OUT_LEN> for KeyedBlake2b {
    fn keyed_hash(k: &[u8; KEY_LEN], data: &[u8], out: &mut [u8; OUT_LEN]) -> Result<(), Error> {
        let mut h = Impl::new_from_slice(k.as_ref()).map_err(|_| Error)?;
        h.update(data);

        let mut tmp = Zeroizing::new([0u8; OUT_LEN]);
        let tmp = GenericArray::from_mut_slice(tmp.as_mut());
        h.finalize_into(tmp);
        copy_slice(tmp.as_ref()).to(out.as_mut());

        Ok(())
    }
}

impl KeyedHashBlake2b for KeyedBlake2b {}
