use std::marker::PhantomData;

/// Models a keyed hash function using an associated function (i.e. without `&self` receiver).
pub trait KeyedHash<const KEY_LEN: usize, const HASH_LEN: usize> {
    /// The error type used to signal what went wrong.
    type Error;

    /// Performs a keyed hash using `key` and `data` and writes the output to `out`
    fn keyed_hash(
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error>;
}

/// Models a keyed hash function using a method (i.e. with a `&self` receiver).
///
/// This makes type inference easier, but also requires having a [`KeyedHashInstance`] value,
/// instead of just the [`KeyedHash`] type.
pub trait KeyedHashInstance<const KEY_LEN: usize, const HASH_LEN: usize> {
    /// The error type used to signal what went wrong.
    type Error;

    /// Performs a keyed hash using `key` and `data` and writes the output to `out`
    fn keyed_hash(
        &self,
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Self::Error>;
}

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
    Static: KeyedHash<KEY_LEN, HASH_LEN>,
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
    ) -> Result<(), Static::Error> {
        Static::keyed_hash(key, data, out)
    }

    pub const fn key_len(self) -> usize {
        Self::KEY_LEN
    }

    pub const fn hash_len(self) -> usize {
        Self::HASH_LEN
    }
}

impl<const KEY_LEN: usize, const HASH_LEN: usize, Static: KeyedHash<KEY_LEN, HASH_LEN>>
    KeyedHashInstance<KEY_LEN, HASH_LEN> for InferKeyedHash<Static, KEY_LEN, HASH_LEN>
{
    type Error = Static::Error;

    fn keyed_hash(
        &self,
        key: &[u8; KEY_LEN],
        data: &[u8],
        out: &mut [u8; HASH_LEN],
    ) -> Result<(), Static::Error> {
        self.keyed_hash_internal(key, data, out)
    }
}

// Helper traits /////////////////////////////////////////////

impl<Static, const KEY_LEN: usize, const OUT_LEN: usize> Default
    for InferKeyedHash<Static, KEY_LEN, OUT_LEN>
where
    Static: KeyedHash<KEY_LEN, OUT_LEN>,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<Static, const KEY_LEN: usize, const OUT_LEN: usize> Clone
    for InferKeyedHash<Static, KEY_LEN, OUT_LEN>
where
    Static: KeyedHash<KEY_LEN, OUT_LEN>,
{
    fn clone(&self) -> Self {
        *self
    }
}

impl<Static, const KEY_LEN: usize, const OUT_LEN: usize> Copy
    for InferKeyedHash<Static, KEY_LEN, OUT_LEN>
where
    Static: KeyedHash<KEY_LEN, OUT_LEN>,
{
}

use rosenpass_to::{with_destination, To};

/// Extends the [`KeyedHash`] trait with a [`To`]-flavoured function.
pub trait KeyedHashTo<const KEY_LEN: usize, const HASH_LEN: usize>:
    KeyedHash<KEY_LEN, HASH_LEN>
{
    fn keyed_hash_to(
        key: &[u8; KEY_LEN],
        data: &[u8],
    ) -> impl To<[u8; HASH_LEN], Result<(), Self::Error>> {
        with_destination(|out| Self::keyed_hash(key, data, out))
    }
}

impl<const KEY_LEN: usize, const HASH_LEN: usize, T: KeyedHash<KEY_LEN, HASH_LEN>>
    KeyedHashTo<KEY_LEN, HASH_LEN> for T
{
}

/// Extends the [`KeyedHashInstance`] trait with a [`To`]-flavoured function.
pub trait KeyedHashInstanceTo<const KEY_LEN: usize, const HASH_LEN: usize>:
    KeyedHashInstance<KEY_LEN, HASH_LEN>
{
    fn keyed_hash_to(
        &self,
        key: &[u8; KEY_LEN],
        data: &[u8],
    ) -> impl To<[u8; HASH_LEN], Result<(), Self::Error>> {
        with_destination(|out| self.keyed_hash(key, data, out))
    }
}

impl<const KEY_LEN: usize, const HASH_LEN: usize, T: KeyedHashInstance<KEY_LEN, HASH_LEN>>
    KeyedHashInstanceTo<KEY_LEN, HASH_LEN> for T
{
}
