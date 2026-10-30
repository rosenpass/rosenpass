use crate::{
    internal::{
        cipher_traits::primitives::kem::Kem, ciphers, secret_memory::PublicBox,
        util::file::LoadValue,
    },
    protocol::basic_types::PublicSymKey,
};
use anyhow::{Context, ensure};
use base64ct::{Base64, Encoding};
use std::{fmt::Debug, marker::PhantomData, path::PathBuf};
use tstr::{IsTStr, TS};

// This import is only used for doc comments.
#[allow(unused_imports)]
use super::RosenpassConfig;

// ============================== user-facing types ==============================

/// a source a keypair consisting of one secret and one public key
///
/// - the secret key is always read from disk ([`KeyFromDisk`])
/// - the public key can be read from different sources (parameter `P`, e.g. [`KeyFromDisk`] or
///   [`KeyFromDiskOrB64EncodedString`])
/// - if keys are read from a directory, the parameters `SFN` (secret file name) and `PFN` (public
///   file name) specify the file inside the directory which should be read
///
/// TODO: more documentation
#[derive(Debug, PartialEq)]
pub struct Keypair<S: SecretKeySource, P: PublicKeySource> {
    pub secret_key_source: S,
    pub public_key_source: P,
}
#[derive(PartialEq)]
pub struct KeyFromDisk<FN: IsTStr, const SIZE: usize> {
    pub inner: KeyFromDiskInner,
    _marker: PhantomData<FN>,
}
#[derive(PartialEq)]
pub struct KeyFromDiskOrB64EncodedString<FN: IsTStr, const SIZE: usize> {
    pub inner: KeyFromDiskOrB64EncodedStringInner,
    _marker: PhantomData<FN>,
}

pub type PqKeypairSource = Keypair<SecretPqKeySource, PublicPqKeySource>;
pub type SecretPqKeySource = KeyFromDisk<TS!("pqsk"), { ciphers::StaticKem::SK_LEN }>;
pub type PublicPqKeySource = KeyFromDisk<TS!("pqpk"), { ciphers::StaticKem::PK_LEN }>;
pub type WgKeypairSource = Keypair<SecretWgKeySource, PublicWgKeySource>;
// TODO: magic numbers for WireGuard key lengths
pub type SecretWgKeySource = KeyFromDisk<TS!("wgsk"), 32>;
pub type PublicWgKeySource = KeyFromDiskOrB64EncodedString<TS!("wgpk"), 32>;

// ============================== inner types ==============================

// improve the Debug output of the user-facing types by hiding the inner types
impl<FN: IsTStr, const SIZE: usize> Debug for KeyFromDisk<FN, SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}
impl<FN: IsTStr, const SIZE: usize> Debug for KeyFromDiskOrB64EncodedString<FN, SIZE> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.inner)
    }
}

// define inner types
#[derive(Debug, PartialEq)]
pub enum KeyFromDiskInner {
    /// the specified path refers to a key **file**
    File(PathBuf),

    /// the specified path refers to a key **directory**
    ///
    /// The name of the key is specified as [`KeyFromDisk`]'s generic parameter `FN`.
    Directory(PathBuf),

    /// no key specified
    ///
    /// This is normally not allowed but the experimental feature `experiment_api` requires to
    /// construct a configuration where the key is added later.
    ///
    /// TODO: this needs to be checked in [`RosenpassConfig::validate`]
    #[cfg(feature = "experiment_api")]
    None,
}
#[derive(Debug, PartialEq)]
pub enum KeyFromDiskOrB64EncodedStringInner {
    /// the specified path refers to a key **file**
    File(PathBuf),

    /// the specified path refers to a key **directory**
    ///
    /// The name of the key is specified as [`KeyFromDiskOrB64EncodedString`]'s generic parameter `FN`.
    Directory(PathBuf),

    /// the specified string is some base64-encoded **public(!)** key
    ///
    /// **WARNING:** this should only be used for public keys as the content of this variant is
    /// **not in secret memory**
    Base64EncodedString(String),

    /// no key specified
    ///
    /// This is normally not allowed but the experimental feature `experiment_api` requires to
    /// construct a configuration where the key is added later.
    ///
    /// TODO: this needs to be checked in [`RosenpassConfig::validate`]
    #[cfg(feature = "experiment_api")]
    None,
}

// implement inner types traits From and [NewFromInner]
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

// ============================== getter functions for key content ==============================
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
            #[cfg(feature = "experiment_api")]
            KeyFromDiskInner::None => todo!(
                "{} {}",
                "How should a key that is not specified be handled?",
                "This occurs because the experimental \"experiment_api\" feature has been enabled."
            ),
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
    ///
    /// - TODO: I think this is also implemented for secret keys(?). It should definitely not be
    ///   called on secret keys...
    ///
    fn get_key(&self) -> Self::GetKeyOutput;

    /// checks whether key source is `None` ([`KeyFromDiskInner::None`] or
    /// [`KeyFromDiskOrB64EncodedStringInner::None`])
    ///
    /// Only relevant if experimenal feature `experiment_api` is enabled. Otherwise the type system
    /// guarantees that the key source is defined.
    #[cfg(feature = "experiment_api")]
    fn is_defined(&self) -> bool;
}
impl<FN: IsTStr, const SIZE: usize> PublicKeySource for KeyFromDisk<FN, SIZE> {
    type GetPathOutput = PathBuf;
    type GetInlineOutput = !;
    type GetKeyOutput = Result<PublicBox<SIZE>, anyhow::Error>;

    fn get_key_path(&self) -> Self::GetPathOutput {
        match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
            #[cfg(feature = "experiment_api")]
            KeyFromDiskInner::None => todo!(
                "{} {}",
                "There is not key set in the configuration which must be a bug.",
                "This occurs because the experimental \"experiment_api\" feature has been enabled."
            ),
        }
    }
    fn get_inline_key(&self) -> Self::GetInlineOutput {
        unimplemented!("this key is always read from disk")
    }
    fn get_key(&self) -> Self::GetKeyOutput {
        // first, determine the key's **file** path
        let path = match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
            #[cfg(feature = "experiment_api")]
            KeyFromDiskInner::None => todo!(
                "{} {}",
                "There is not key set in the configuration which must be a bug.",
                "This occurs because the experimental \"experiment_api\" feature has been enabled."
            ),
        };
        // load key from disk
        PublicBox::load(path)
    }
    #[cfg(feature = "experiment_api")]
    fn is_defined(&self) -> bool {
        match &self.inner {
            KeyFromDiskInner::File(_) => true,
            KeyFromDiskInner::Directory(_) => true,
            KeyFromDiskInner::None => false,
        }
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
            #[cfg(feature = "experiment_api")]
            KeyFromDiskOrB64EncodedStringInner::None => todo!(
                "{} {}",
                "How should a key that is not specified be handled?",
                "This occurs because the experimental \"experiment_api\" feature has been enabled."
            ),
        }
    }
    fn get_inline_key(&self) -> Self::GetInlineOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(_file) => None,
            KeyFromDiskOrB64EncodedStringInner::Directory(_dir) => None,
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(raw) => Some(raw.clone()),
            #[cfg(feature = "experiment_api")]
            KeyFromDiskOrB64EncodedStringInner::None => todo!(
                "{} {}",
                "How should a key that is not specified be handled?",
                "This occurs because the experimental \"experiment_api\" feature has been enabled."
            ),
        }
    }
    fn get_key(&self) -> Self::GetKeyOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(file) => PublicBox::load(file),
            KeyFromDiskOrB64EncodedStringInner::Directory(dir) => {
                PublicBox::load(dir.join(FN::STR))
            }
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(raw) => {
                todo!() // a similar implementation is used in config::decode_wg_pubkey_b64
            }
            #[cfg(feature = "experiment_api")]
            KeyFromDiskOrB64EncodedStringInner::None => todo!(
                "{} {}",
                "How should a key that is not specified be handled?",
                "This occurs because the experimental \"experiment_api\" feature has been enabled."
            ),
        }
    }
    #[cfg(feature = "experiment_api")]
    fn is_defined(&self) -> bool {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(_) => true,
            KeyFromDiskOrB64EncodedStringInner::Directory(_) => true,
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(_) => true,
            KeyFromDiskOrB64EncodedStringInner::None => false,
        }
    }
}

// ============================== base64-decode WG public keys ==============================
/// decode a base64-encoded WireGuard public key (32 bytes) into a [`PublicSymKey`]
pub fn decode_wg_pubkey_b64(b64_encoded_key: &str) -> anyhow::Result<PublicSymKey> {
    let mut pubkey: PublicSymKey = [0u8; _];

    let decoded_len = Base64::decode(b64_encoded_key, &mut pubkey)
        .context("can not decode base64-encoded WireGuard public key")?
        .len();

    ensure!(
        decoded_len == pubkey.len(),
        "invalid WireGuard public key length: expected {} bytes, got {decoded_len} bytes",
        pubkey.len()
    );

    Ok(pubkey)
}
#[cfg(test)]
mod test_decode_wg_pubkey_b64 {
    use super::{Base64, Encoding, decode_wg_pubkey_b64};

    // valid WireGuard public key: 32 decoded bytes public X25519 key
    const VALID: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmo=";
    // invalid WireGuard public keys
    const TOO_SHORT: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTg==";
    const TOO_LONG: &str = "hSDwCYkwp1R0i33ctD73Wg2/Og0mOBr066SpjqqbTmoA";
    // TODO: add more tests

    #[test]
    fn test_decode_wg_pubkey_b64() {
        let decoded = decode_wg_pubkey_b64(VALID).unwrap();
        let mut reencoded: [u8; _] = [0; 44];
        Base64::encode(&decoded, &mut reencoded).unwrap();
        let reencoded = String::from_utf8(reencoded.to_vec()).unwrap();
        assert_eq!(reencoded.as_str(), VALID);
    }

    #[test]
    #[should_panic = "can not decode base64-encoded WireGuard public key"]
    fn test_decode_wg_pubkey_b64_rejects_too_long() {
        decode_wg_pubkey_b64(TOO_LONG).unwrap();
    }

    #[test]
    #[should_panic = "invalid WireGuard public key length: expected 32 bytes, got 31 bytes"]
    fn test_decode_wg_pubkey_b64_rejects_too_short() {
        decode_wg_pubkey_b64(TOO_SHORT).unwrap();
    }
}
