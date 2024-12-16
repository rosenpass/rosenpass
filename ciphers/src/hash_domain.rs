use anyhow::Result;
use rosenpass_secret_memory::Secret;
use rosenpass_to::To;

use crate::keyed_hash as hash;

pub use hash::KEY_LEN;

///
///```rust
/// # use rosenpass_ciphers::hash_domain::{HashDomain, HashDomainNamespace, SecretHashDomain, SecretHashDomainNamespace};
/// use rosenpass_secret_memory::Secret;
/// # rosenpass_secret_memory::secret_policy_use_only_malloc_secrets();
///
/// const PROTOCOL_IDENTIFIER: &str = "MY_PROTOCOL:IDENTIFIER";
/// // create use once hash domain for the protocol identifier
/// let mut hash_domain = HashDomain::zero();
/// hash_domain = hash_domain.mix(PROTOCOL_IDENTIFIER.as_bytes())?;
/// // upgrade to reusable hash domain
/// let hash_domain_namespace: HashDomainNamespace = hash_domain.dup();
/// // derive new key
/// let key_identifier = "my_key_identifier";
/// let key = hash_domain_namespace.mix(key_identifier.as_bytes())?.into_value();
/// // derive a new key based on a secret
/// const MY_SECRET_LEN: usize = 21;
/// let my_secret_bytes = "my super duper secret".as_bytes();
/// let my_secret: Secret<21> = Secret::from_slice("my super duper secret".as_bytes());
/// let secret_hash_domain: SecretHashDomain = hash_domain_namespace.mix_secret(my_secret)?;
/// // derive a new key based on the secret key
/// let new_key_identifier = "my_new_key_identifier".as_bytes();
/// let new_key = secret_hash_domain.mix(new_key_identifier)?.into_secret();
///
/// # Ok::<(), anyhow::Error>(())
///```
///

// TODO Use a proper Dec interface
/// A use-once hash domain for a specified key that can be used directly.
/// The key must consist of [KEY_LEN] many bytes. If the key must remain secret,
/// use [SecretHashDomain] instead.
#[derive(Clone, Debug)]
pub struct HashDomain([u8; KEY_LEN]);
/// A reusable hash domain for a namespace identified by the key.
/// The key must consist of [KEY_LEN] many bytes. If the key must remain secret,
/// use [SecretHashDomainNamespace] instead.
#[derive(Clone, Debug)]
pub struct HashDomainNamespace([u8; KEY_LEN]);
/// A use-once hash domain for a specified key that can be used directly
/// by wrapping it in [Secret]. The key must consist of [KEY_LEN] many bytes.
#[derive(Clone, Debug)]
pub struct SecretHashDomain(Secret<KEY_LEN>);
/// A reusable secure hash domain for a namespace identified by the key and that keeps the key secure
/// by wrapping it in [Secret]. The key must consist of [KEY_LEN] many bytes.
#[derive(Clone, Debug)]
pub struct SecretHashDomainNamespace(Secret<KEY_LEN>);

impl HashDomain {
    /// Creates a nw [HashDomain] initialized with a all-zeros key.
    pub fn zero() -> Self {
        Self([0u8; KEY_LEN])
    }

    /// Turns this [HashDomain] into a [HashDomainNamespace], keeping the key.
    pub fn dup(self) -> HashDomainNamespace {
        HashDomainNamespace(self.0)
    }

    /// Turns this [HashDomain] into a [SecretHashDomain] by wrapping the key into a [Secret]
    /// and creating a new [SecretHashDomain] from it.
    pub fn turn_secret(self) -> SecretHashDomain {
        SecretHashDomain(Secret::from_slice(&self.0))
    }

    // TODO: Protocol! Use domain separation to ensure that
    /// Creates a new [HashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with this HashDomain's key as the key and `v`
    /// as the `data` and uses the result as the key for the new [HashDomain].
    ///
    pub fn mix(self, v: &[u8]) -> Result<Self> {
        Ok(Self(hash::hash(&self.0, v).collect::<[u8; KEY_LEN]>()?))
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with this
    /// [HashDomain]'s key as `k` and `v` as `d`.
    pub fn mix_secret<const N: usize>(self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(&self.0, v.secret())
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
        Ok(HashDomain(
            hash::hash(&self.0, v).collect::<[u8; KEY_LEN]>()?,
        ))
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with the key of this
    /// [HashDomainNamespace] as `k` and `v` as `d`.
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix_secret<const N: usize>(&self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(&self.0, v.secret())
    }
}

impl SecretHashDomain {
    /// Create a new [SecretHashDomain] with the given key `k` and data `d` by calling
    /// [hash::hash] with `k` as the `key` and `d` s the `data`, and using the result
    /// as the content for the new [SecretHashDomain].
    /// Both `k` and `d` have to be exactly [KEY_LEN] bytes in length.
    pub fn invoke_primitive(k: &[u8], d: &[u8]) -> Result<SecretHashDomain> {
        let mut r = SecretHashDomain(Secret::zero());
        hash::hash(k, d).to(r.0.secret_mut())?;
        Ok(r)
    }

    /// Creates a new [SecretHashDomain] that is initialized with an all zeros key.
    pub fn zero() -> Self {
        Self(Secret::zero())
    }

    /// Turns this [SecretHashDomain] into a [SecretHashDomainNamespace].
    pub fn dup(self) -> SecretHashDomainNamespace {
        SecretHashDomainNamespace(self.0)
    }

    /// Creates a new [SecretHashDomain] from a [Secret] `k`.
    ///
    /// It requires that `k` consist of exactly [KEY_LEN] bytes.
    pub fn danger_from_secret(k: Secret<KEY_LEN>) -> Self {
        Self(k)
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with this [SecretHashDomain]'s key as the key and `v`
    /// as the `data` and uses the result as the key for the new [SecretHashDomain].
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix(self, v: &[u8]) -> Result<SecretHashDomain> {
        Self::invoke_primitive(self.0.secret(), v)
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with the key of this
    /// [HashDomainNamespace] as `k` and `v` as `d`.
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix_secret<const N: usize>(self, v: Secret<N>) -> Result<SecretHashDomain> {
        Self::invoke_primitive(self.0.secret(), v.secret())
    }

    /// Get the secret key data from this [SecretHashDomain].
    pub fn into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }

    /// Evaluate [hash::hash] with this [SecretHashDomain]'s data as the `key` and
    /// `dst` as the `data` and stores the result as the new data for this [SecretHashDomain].
    ///
    /// It requires that both `v` and `d` consist of exactly [KEY_LEN] many bytes.
    pub fn into_secret_slice(mut self, v: &[u8], dst: &[u8]) -> Result<()> {
        hash::hash(v, dst).to(self.0.secret_mut())
    }
}

impl SecretHashDomainNamespace {
    /// Creates a new [SecretHashDomain] by mixing in a new key `v`. Specifically,
    /// it evaluates [hash::hash] with the key of this HashDomainNamespace key as the key and `v`
    /// as the `data` and uses the result as the key for the new [HashDomain].
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix(&self, v: &[u8]) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(self.0.secret(), v)
    }

    /// Creates a new [SecretHashDomain] by mixing in a new key `v`
    /// by calling [SecretHashDomain::invoke_primitive] with the key of this
    /// [HashDomainNamespace] as `k` and `v` as `d`.
    ///
    /// It requires that `v` consists of exactly [KEY_LEN] many bytes.
    pub fn mix_secret<const N: usize>(&self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(self.0.secret(), v.secret())
    }

    // TODO: This entire API is not very nice; we need this for biscuits, but
    // it might be better to extract a special "biscuit"
    // labeled subkey and reinitialize the chain with this
    /// Get the secret key data from this [SecretHashDomain].
    pub fn danger_into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }
}
