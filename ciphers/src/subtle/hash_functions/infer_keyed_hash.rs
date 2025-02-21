use anyhow::Result;
use rosenpass_cipher_traits::{KeyedHash, KeyedHashInstance};
use std::marker::PhantomData;

/// This is a helper to allow for type parameter inference when calling functions
/// that need a [KeyedHash].
///
/// Really just binds the [KeyedHash] trait to a dummy variable, so the type of this dummy variable
/// can be used for type inference. Less typing work.
#[derive(Debug, PartialEq, Eq)]
pub struct InferKeyedHash<Static, const KEY_LEN: usize, const HASH_LEN: usize>
where
    Static: KeyedHash<KEY_LEN, HASH_LEN>,
{
    pub _phantom_keyed_hasher: PhantomData<*const Static>,
}

impl<Static, const KEY_LEN: usize, const HASH_LEN: usize> InferKeyedHash<Static, KEY_LEN, HASH_LEN>
where
    Static: KeyedHash<KEY_LEN, HASH_LEN, Error = anyhow::Error>,
{
    pub const KEY_LEN: usize = KEY_LEN;
    pub const HASH_LEN: usize = HASH_LEN;

    pub const fn new() -> Self {
        Self {
            _phantom_keyed_hasher: PhantomData,
        }
    }

    /// This just forwards to [KeyedHash::keyed_hash] of the type parameter `Static`
    fn keyed_hash_internal<'a>(
        &self,
        key: &'a [u8; KEY_LEN],
        data: &'a [u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<()> {
        Static::keyed_hash(key, data, out)
    }

    pub const fn key_len(self) -> usize {
        Self::KEY_LEN
    }

    pub const fn hash_len(self) -> usize {
        Self::HASH_LEN
    }
}

impl<
        const KEY_LEN: usize,
        const HASH_LEN: usize,
        Static: KeyedHash<KEY_LEN, HASH_LEN, Error = anyhow::Error>,
    > KeyedHashInstance<KEY_LEN, HASH_LEN> for InferKeyedHash<Static, KEY_LEN, HASH_LEN>
{
    type KeyType = [u8; KEY_LEN];
    type OutputType = [u8; HASH_LEN];
    type Error = anyhow::Error;

    fn keyed_hash(&self, key: &[u8; KEY_LEN], data: &[u8], out: &mut [u8; HASH_LEN]) -> Result<()> {
        self.keyed_hash_internal(key, data, out)
    }
}

/// Helper traits /////////////////////////////////////////////

impl<Static, const KEY_LEN: usize, const OUT_LEN: usize> Default
    for InferKeyedHash<Static, KEY_LEN, OUT_LEN>
where
    Static: KeyedHash<KEY_LEN, OUT_LEN, Error = anyhow::Error>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Static, const KEY_LEN: usize, const OUT_LEN: usize> Clone
    for InferKeyedHash<Static, KEY_LEN, OUT_LEN>
where
    Static: KeyedHash<KEY_LEN, OUT_LEN, Error = anyhow::Error>,
{
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<Static, const KEY_LEN: usize, const OUT_LEN: usize> Copy
    for InferKeyedHash<Static, KEY_LEN, OUT_LEN>
where
    Static: KeyedHash<KEY_LEN, OUT_LEN, Error = anyhow::Error>,
{
}
