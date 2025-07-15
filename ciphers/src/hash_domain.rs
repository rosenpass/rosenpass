//!
//!```rust
//! # use rosenpass_ciphers::hash_domain::{HashDomain, HashDomainNamespace, SecretHashDomain, SecretHashDomainNamespace};
//! use rosenpass_ciphers::KeyedHash;
//! use rosenpass_secret_memory::Secret;
//! # rosenpass_secret_memory::secret_policy_use_only_malloc_secrets();
//!
//! const PROTOCOL_IDENTIFIER: &str = "MY_PROTOCOL:IDENTIFIER";
//! // create use once hash domain for the protocol identifier
//! let mut hash_domain = HashDomain::zero(KeyedHash::keyed_shake256());
//! hash_domain = hash_domain.mix(PROTOCOL_IDENTIFIER.as_bytes())?;
//! // upgrade to reusable hash domain
//! let hash_domain_namespace: HashDomainNamespace = hash_domain.dup();
//! // derive new key
//! let key_identifier = "my_key_identifier";
//! let key = hash_domain_namespace.mix(key_identifier.as_bytes())?.into_value();
//! // derive a new key based on a secret
//! const MY_SECRET_LEN: usize = 21;
//! let my_secret_bytes = "my super duper secret".as_bytes();
//! let my_secret: Secret<21> = Secret::from_slice("my super duper secret".as_bytes());
//! let secret_hash_domain: SecretHashDomain = hash_domain_namespace.mix_secret(my_secret)?;
//! // derive a new key based on the secret key
//! let new_key_identifier = "my_new_key_identifier".as_bytes();
//! let new_key = secret_hash_domain.mix(new_key_identifier)?.into_secret();
//!
//! # Ok::<(), anyhow::Error>(())
//!```
//!

use anyhow::Result;
use rosenpass_secret_memory::Secret;
use rosenpass_to::To as _;

pub use crate::{KeyedHash, KEY_LEN};

use rosenpass_cipher_traits::primitives::KeyedHashInstanceTo;

// TODO Use a proper Dec interface
/// A use-once hash domain for a specified key that can be used directly.
/// The key must consist of [KEY_LEN] many bytes. If the key must remain secret,
/// use [SecretHashDomain] instead.
#[derive(Clone, Debug)]
pub struct HashDomain([u8; KEY_LEN], KeyedHash);
/// A reusable hash domain for a namespace identified by the key.
/// The key must consist of [KEY_LEN] many bytes. If the key must remain secret,
/// use [SecretHashDomainNamespace] instead.
#[derive(Clone, Debug)]
pub struct HashDomainNamespace([u8; KEY_LEN], KeyedHash);
/// A use-once hash domain for a specified key that can be used directly
/// by wrapping it in [Secret]. The key must consist of [KEY_LEN] many bytes.
#[derive(Clone, Debug)]
pub struct SecretHashDomain(Secret<KEY_LEN>, KeyedHash);
/// A reusable secure hash domain for a namespace identified by the key and that keeps the key secure
/// by wrapping it in [Secret]. The key must consist of [KEY_LEN] many bytes.
#[derive(Clone, Debug)]
pub struct SecretHashDomainNamespace(Secret<KEY_LEN>, KeyedHash);

impl HashDomain {
    /// Creates a nw [HashDomain] initialized with a all-zeros key.
    pub fn zero(choice: KeyedHash) -> Self {
        Self([0u8; KEY_LEN], choice)
    }

    /// Turns this [HashDomain] into a [HashDomainNamespace], keeping the key.
    pub fn dup(self) -> HashDomainNamespace {
        HashDomainNamespace(self.0, self.1)
    }

    /// Turns this [HashDomain] into a [SecretHashDomain] by wrapping the key into a [Secret]
    /// and creating a new [SecretHashDomain] from it.
    pub fn turn_secret(self) -> SecretHashDomain {
        SecretHashDomain(Secret::from_slice(&self.0), self.1)
    }

    // TODO: Protocol! Use domain separation to ensure that
    /// Creates a new [HashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with this HashDomain's key as the key and `v`
    /// as the `data` and uses the result as the key for the new [HashDomain].
    ///
    pub fn mix(self, v: &[u8]) -> Result<Self> {
        let mut new_key: [u8; KEY_LEN] = [0u8; KEY_LEN];
        self.1.keyed_hash_to(&self.0, v).to(&mut new_key)?;
        Ok(Self(new_key, self.1))
    }

    /// Version of [Self::mix] that accepts an iterator and mixes all values from the iterator into
    /// this hash domain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rosenpass_ciphers::{hash_domain::HashDomain, KeyedHash};
    ///
    /// let hasher = HashDomain::zero(KeyedHash::keyed_shake256());
    /// assert_eq!(
    ///     hasher.clone().mix(b"Hello")?.mix(b"World")?.into_value(),
    ///     hasher.clone().mix_many([b"Hello", b"World"])?.into_value()
    /// );
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    pub fn mix_many<I, T>(mut self, it: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        for e in it {
            self = self.mix(e.as_ref())?;
        }
        Ok(self)
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with this
    /// [HashDomain]'s key as `k` and `v` as `d`.
    pub fn mix_secret<const N: usize>(self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(&self.0, v.secret(), self.1)
    }

    /// Gets the key of this [HashDomain].
    pub fn into_value(self) -> [u8; KEY_LEN] {
        self.0
    }
}

impl HashDomainNamespace {
    /// Creates a new [HashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with the key of this HashDomainNamespace key as the key and `v`
    /// as the `data` and uses the result as the key for the new [HashDomain].
    pub fn mix(&self, v: &[u8]) -> Result<HashDomain> {
        let mut new_key: [u8; KEY_LEN] = [0u8; KEY_LEN];
        self.1.keyed_hash_to(&self.0, v).to(&mut new_key)?;
        Ok(HashDomain(new_key, self.1.clone()))
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with the key of this
    /// [HashDomainNamespace] as `k` and `v` as `d`.
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix_secret<const N: usize>(&self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(&self.0, v.secret(), self.1.clone())
    }
}

impl SecretHashDomain {
    /// Create a new [SecretHashDomain] with the given key `k` and data `d` by calling
    /// [hash::hash] with `k` as the `key` and `d` s the `data`, and using the result
    /// as the content for the new [SecretHashDomain].
    /// Both `k` and `d` have to be exactly [KEY_LEN] bytes in length.
    /// TODO: docu
    pub fn invoke_primitive(
        k: &[u8],
        d: &[u8],
        hash_choice: KeyedHash,
    ) -> Result<SecretHashDomain> {
        let mut new_secret_key = Secret::zero();
        hash_choice
            .keyed_hash_to(k.try_into()?, d)
            .to(new_secret_key.secret_mut())?;
        let r = SecretHashDomain(new_secret_key, hash_choice);
        Ok(r)
    }

    /// Creates a new [SecretHashDomain] that is initialized with an all zeros key.
    pub fn zero(hash_choice: KeyedHash) -> Self {
        Self(Secret::zero(), hash_choice)
    }

    /// Turns this [SecretHashDomain] into a [SecretHashDomainNamespace].
    pub fn dup(self) -> SecretHashDomainNamespace {
        SecretHashDomainNamespace(self.0, self.1)
    }

    /// Creates a new [SecretHashDomain] from a [Secret] `k`.
    ///
    /// It requires that `k` consist of exactly [KEY_LEN] bytes.
    pub fn danger_from_secret(k: Secret<KEY_LEN>, hash_choice: KeyedHash) -> Self {
        Self(k, hash_choice)
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with this [SecretHashDomain]'s key as the key and `v`
    /// as the `data` and uses the result as the key for the new [SecretHashDomain].
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix(self, v: &[u8]) -> Result<SecretHashDomain> {
        Self::invoke_primitive(self.0.secret(), v, self.1)
    }

    /// Version of [Self::mix] that accepts an iterator and mixes all values from the iterator into
    /// this hash domain.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use rosenpass_ciphers::{hash_domain::HashDomain, KeyedHash};
    ///
    /// rosenpass_secret_memory::secret_policy_use_only_malloc_secrets();
    ///
    /// let hasher = HashDomain::zero(KeyedHash::keyed_shake256());
    /// assert_eq!(
    ///     hasher
    ///         .clone()
    ///         .turn_secret()
    ///         .mix(b"Hello")?
    ///         .mix(b"World")?
    ///         .into_secret()
    ///         .secret(),
    ///     hasher
    ///         .clone()
    ///         .turn_secret()
    ///         .mix_many([b"Hello", b"World"])?
    ///         .into_secret()
    ///         .secret(),
    /// );

    /// Ok::<(), anyhow::Error>(())
    /// ```
    pub fn mix_many<I, T>(mut self, it: I) -> Result<Self>
    where
        I: IntoIterator<Item = T>,
        T: AsRef<[u8]>,
    {
        for e in it {
            self = self.mix(e.as_ref())?;
        }
        Ok(self)
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with the key of this
    /// [HashDomainNamespace] as `k` and `v` as `d`.
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix_secret<const N: usize>(self, v: Secret<N>) -> Result<SecretHashDomain> {
        Self::invoke_primitive(self.0.secret(), v.secret(), self.1)
    }

    /// Get the secret key data from this [SecretHashDomain].
    pub fn into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }
}

impl SecretHashDomainNamespace {
    /// Creates a new [SecretHashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with the key of this HashDomainNamespace key as the key and `v`
    /// as the `data` and uses the result as the key for the new [HashDomain].
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix(&self, v: &[u8]) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(self.0.secret(), v, self.1.clone())
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with the key of this
    /// [HashDomainNamespace] as `k` and `v` as `d`.
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix_secret<const N: usize>(&self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(self.0.secret(), v.secret(), self.1.clone())
    }

    // TODO: This entire API is not very nice; we need this for biscuits, but
    // it might be better to extract a special "biscuit"
    // labeled subkey and reinitialize the chain with this
    /// Get the secret key data from this [SecretHashDomain].
    pub fn danger_into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }

    pub fn keyed_hash(&self) -> &KeyedHash {
        &self.1
    }
}
