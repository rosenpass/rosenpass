use std::{marker::PhantomData, path::PathBuf};

use tstr::{IsTStr, TS};

use crate::internal::secret_memory::PublicBox;
use crate::internal::util::file::{LoadValue, LoadValueB64};
use crate::internal::{cipher_traits::primitives::kem::Kem, ciphers};

/// a source a keypair consisting of one secret and one public key
///
/// - the secret key is always read from disk ([`KeyFromDisk`])
/// - the public key can be read from different sources (parameter `P`, e.g. [`KeyFromDisk`] or
///   [`KeyFromDiskOrB64EncodedString`])
/// - if keys are read from a directory, the parameters `SFN` (secret file name) and `PFN` (public
///   file name) specify the file inside the directory which should be read
///
/// TODO: more documentation
#[derive(Debug)]
pub struct Keypair<S: SecretKeySource, P: PublicKeySource> {
    pub secret_key_source: S,
    pub public_key_source: P,
}
#[derive(Debug)]
pub enum KeyFromDiskInner {
    File(PathBuf),
    Directory(PathBuf),
}
#[derive(Debug)]
pub struct KeyFromDisk<FN: IsTStr, const SIZE: usize> {
    pub inner: KeyFromDiskInner,
    _marker: PhantomData<FN>,
}
#[derive(Debug)]
pub enum KeyFromDiskOrB64EncodedStringInner {
    File(PathBuf),
    Directory(PathBuf),
    Base64EncodedString(String),
}
#[derive(Debug)]
pub struct KeyFromDiskOrB64EncodedString<FN: IsTStr, const SIZE: usize> {
    pub inner: KeyFromDiskOrB64EncodedStringInner,
    _marker: PhantomData<FN>,
}
pub type PqKeypairSource = Keypair<SecretPqKeySource, PublicPqKeySource>;
pub type SecretPqKeySource = KeyFromDisk<TS!("pqsk"), { ciphers::StaticKem::SK_LEN }>;
pub type PublicPqKeySource = KeyFromDisk<TS!("pqsk"), { ciphers::StaticKem::PK_LEN }>;
pub type WgKeypairSource = Keypair<SecretWgKeySource, PublicWgKeySource>;
// TODO: magic numbers for WireGuard key lengths
pub type SecretWgKeySource = KeyFromDisk<TS!("wgsk"), 32>;
pub type PublicWgKeySource = KeyFromDiskOrB64EncodedString<TS!("wgpk"), { 32 }>;

pub trait HasInnerType: Sized {
    type InnerType;
}
impl<FN: IsTStr, const SIZE: usize> HasInnerType for KeyFromDisk<FN, SIZE> {
    type InnerType = KeyFromDiskInner;
}
impl<FN: IsTStr, const SIZE: usize> HasInnerType for KeyFromDiskOrB64EncodedString<FN, SIZE> {
    type InnerType = KeyFromDiskOrB64EncodedStringInner;
}
pub trait NewFromInner: HasInnerType + From<Self::InnerType> {
    fn new(inner: Self::InnerType) -> Self {
        Self::from(inner)
    }
}
impl<T> NewFromInner for T where T: HasInnerType + From<T::InnerType> {}
impl<FN: IsTStr, const SIZE: usize> From<KeyFromDiskInner> for KeyFromDisk<FN, SIZE> {
    fn from(value: KeyFromDiskInner) -> Self {
        KeyFromDisk {
            inner: value,
            _marker: Default::default(),
        }
    }
}
impl<FN: IsTStr, const SIZE: usize> From<KeyFromDiskOrB64EncodedStringInner>
    for KeyFromDiskOrB64EncodedString<FN, SIZE>
{
    fn from(value: KeyFromDiskOrB64EncodedStringInner) -> Self {
        KeyFromDiskOrB64EncodedString {
            inner: value,
            _marker: Default::default(),
        }
    }
}

pub trait SecretKeySource {
    fn get_secret_key_path(&self) -> PathBuf;
    // TODO:
    // fn get_key(&self, length: usize) -> Self::GetKeyOutput;
}
impl<FN: IsTStr, const SIZE: usize> SecretKeySource for KeyFromDisk<FN, SIZE> {
    fn get_secret_key_path(&self) -> PathBuf {
        match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
        }
    }
}
pub trait PublicKeySource {
    type GetPathOutput;
    type GetInlineOutput;
    type GetKeyOutput;

    /// returns the path to the key file (if the key is specified via file or directory)
    fn get_key_path(&self) -> Self::GetPathOutput;

    /// return the raw inline key data from the config file (if the key is specified inline)
    ///
    /// NOTE: these data might be encoded, e.g. with Base64
    fn get_inline_key(&self) -> Self::GetInlineOutput;

    /// returns the key data
    fn get_key(&self) -> Self::GetKeyOutput;
}
impl<FN: IsTStr, const SIZE: usize> PublicKeySource for KeyFromDisk<FN, SIZE> {
    type GetPathOutput = PathBuf;
    type GetInlineOutput = !;
    type GetKeyOutput = Result<PublicBox<SIZE>, anyhow::Error>;

    fn get_key_path(&self) -> Self::GetPathOutput {
        match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
        }
    }
    fn get_inline_key(&self) -> Self::GetInlineOutput {
        unimplemented!("this key is always read from disk")
    }
    fn get_key(&self) -> Self::GetKeyOutput {
        let path = match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
        };
        PublicBox::load(path)
    }
}
impl<FN: IsTStr, const SIZE: usize> PublicKeySource for KeyFromDiskOrB64EncodedString<FN, SIZE> {
    type GetPathOutput = Option<PathBuf>;
    type GetInlineOutput = Option<String>;
    type GetKeyOutput = Result<PublicBox<SIZE>, anyhow::Error>;
    fn get_key_path(&self) -> Self::GetPathOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(file) => Some(file.clone()),
            KeyFromDiskOrB64EncodedStringInner::Directory(dir) => Some(dir.join(FN::STR)),
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(_raw) => None,
        }
    }
    fn get_inline_key(&self) -> Self::GetInlineOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(_file) => None,
            KeyFromDiskOrB64EncodedStringInner::Directory(_dir) => None,
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(raw) => Some(raw.clone()),
        }
    }
    fn get_key(&self) -> Self::GetKeyOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(file) => PublicBox::load(file),
            KeyFromDiskOrB64EncodedStringInner::Directory(dir) => {
                PublicBox::load(dir.join(FN::STR))
            }
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(raw) => {
                todo!() // a similar implementation is used in oldconfig::decode_wg_pubkey_b64
            }
        }
    }
}
