use zeroize::Zeroizing;

use blake2::digest::crypto_common::generic_array::GenericArray;
use blake2::digest::crypto_common::typenum::U32;
use blake2::digest::crypto_common::KeySizeUser;
use blake2::digest::{FixedOutput, Mac, OutputSizeUser};
use blake2::Blake2bMac;

use rosenpass_to::{ops::copy_slice, with_destination, To};
use rosenpass_util::typenum2const;

type Impl = Blake2bMac<U32>;

type KeyLen = <Impl as KeySizeUser>::KeySize;
type OutLen = <Impl as OutputSizeUser>::OutputSize;

const KEY_LEN: usize = typenum2const! { KeyLen };
const OUT_LEN: usize = typenum2const! { OutLen };

pub const KEY_MIN: usize = KEY_LEN;
pub const KEY_MAX: usize = KEY_LEN;
pub const OUT_MIN: usize = OUT_LEN;
pub const OUT_MAX: usize = OUT_LEN;

#[inline]
pub fn hash<'a>(key: &'a [u8], data: &'a [u8]) -> impl To<[u8], anyhow::Result<()>> + 'a {
    with_destination(|out: &mut [u8]| {
        let mut h = Impl::new_from_slice(key)?;
        h.update(data);

        // Jesus christ, blake2 crate, your usage of GenericArray might be nice and fancy
        // but it introduces a ton of complexity. This cost me half an hour just to figure
        // out the right way to use the imports while allowing for zeroization.
        // An API based on slices might actually be simpler.
        let mut tmp = Zeroizing::new([0u8; OUT_LEN]);
        let mut tmp = GenericArray::from_mut_slice(tmp.as_mut());
        h.finalize_into(&mut tmp);
        copy_slice(tmp.as_ref()).to(out);

        Ok(())
    })
}
