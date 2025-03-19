//! Implementation of the [`KeyedHashBlake2b`] trait based on the [`libcrux_blake2`] crate.

use libcrux_blake2::Blake2bBuilder;

use rosenpass_cipher_traits::algorithms::KeyedHashBlake2b;
use rosenpass_cipher_traits::primitives::KeyedHash;

pub use rosenpass_cipher_traits::algorithms::keyed_hash_blake2b::HASH_LEN;
pub use rosenpass_cipher_traits::algorithms::keyed_hash_blake2b::KEY_LEN;

/// Describles which error occurred
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// An unexpected internal error occurred. Should never be returned and points to a bug in the
    /// implementation.
    #[error("internal error")]
    InternalError,

    /// Indicates that the provided data was too long.
    #[error("data is too long")]
    DataTooLong,
}

/// Hasher for the given `data` with the Blake2b hash function.
pub struct Blake2b;

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

#[cfg(test)]
mod equivalence_tests {
    use super::*;
    use rand::RngCore;

    #[test]
    fn fuzz_equivalence_libcrux_old_new() {
        let datas: [&[u8]; 3] = [
            b"".as_slice(),
            b"test".as_slice(),
            b"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd",
        ];

        let mut key = [0; KEY_LEN];
        let mut rng = rand::thread_rng();

        let mut hash_left = [0; 32];
        let mut hash_right = [0; 32];

        for data in datas {
            for _ in 0..1000 {
                rng.fill_bytes(&mut key);

                crate::subtle::rust_crypto::blake2b::Blake2b::keyed_hash(
                    &key,
                    data,
                    &mut hash_left,
                )
                .unwrap();
                crate::subtle::libcrux::blake2b::Blake2b::keyed_hash(&key, data, &mut hash_right)
                    .unwrap();

                assert_eq!(hash_left, hash_right);
            }
        }
    }
}
