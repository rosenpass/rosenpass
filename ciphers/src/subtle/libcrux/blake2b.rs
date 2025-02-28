use rosenpass_cipher_traits::algorithms::KeyedHashBlake2b;
use rosenpass_cipher_traits::primitives::KeyedHash;

use libcrux_blake2::Blake2bBuilder;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("internal error")]
    InternalError,
    #[error("data is too long")]
    DataTooLong,
}

pub struct Blake2b;

pub const KEY_LEN: usize = 32;
pub const HASH_LEN: usize = 32;

impl KeyedHash<KEY_LEN, HASH_LEN> for Blake2b {
    type Error = Error;

    fn keyed_hash(
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        let mut h = Blake2bBuilder::new_keyed_const(key)
            // this may fail if the key length is invalid, but 32 is fine
            .map_err(|_| Error::InternalError)?
            .build_const_digest_len()
            .map_err(|_|
            // this can only fail if the output length is invalid, but 32 is fine.
            Error::InternalError)?;

        h.update(data).map_err(|_| Error::DataTooLong)?;
        h.finalize(out);

        Ok(())
    }
}

impl KeyedHashBlake2b for Blake2b {}
