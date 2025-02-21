use crate::subtle::hash_functions::keyed_shake256::SHAKE256Core;
use crate::subtle::incorrect_hmac_blake2b::Blake2bCore;
use anyhow::Result;
use rosenpass_cipher_traits::{KeyedHash, KeyedHashInstance};

#[derive(Debug, Eq, PartialEq)]
pub enum EitherHash<
    const KEY_LEN: usize,
    const HASH_LEN: usize,
    Error,
    L: KeyedHash<KEY_LEN, HASH_LEN, Error = Error>,
    R: KeyedHash<KEY_LEN, HASH_LEN, Error = Error>,
> {
    Left(L),
    Right(R),
}

impl<const KEY_LEN: usize, const HASH_LEN: usize, Error, L, R> KeyedHashInstance<KEY_LEN, HASH_LEN>
    for EitherHash<KEY_LEN, HASH_LEN, Error, L, R>
where
    L: KeyedHash<KEY_LEN, HASH_LEN, Error = Error>,
    R: KeyedHash<KEY_LEN, HASH_LEN, Error = Error>,
{
    type KeyType = [u8; KEY_LEN];
    type OutputType = [u8; HASH_LEN];
    type Error = Error;

    fn keyed_hash(
        &self,
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error> {
        match self {
            Self::Left(_) => L::keyed_hash(key, data, out),
            Self::Right(_) => R::keyed_hash(key, data, out),
        }
    }
}

pub type EitherShakeOrBlake = EitherHash<32, 32, anyhow::Error, SHAKE256Core<32, 32>, Blake2bCore>;

impl Clone for EitherShakeOrBlake {
    fn clone(&self) -> Self {
        match self {
            Self::Left(l) => Self::Left(l.clone()),
            Self::Right(r) => Self::Right(r.clone()),
        }
    }
}
