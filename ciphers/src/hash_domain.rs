use anyhow::Result;
use rosenpass_secret_memory::Secret;
use rosenpass_to::To;

use crate::keyed_hash as hash;

pub use hash::KEY_LEN;

// TODO Use a proper Dec interface
#[derive(Clone, Debug)]
pub struct HashDomain([u8; KEY_LEN]);
#[derive(Clone, Debug)]
pub struct HashDomainNamespace([u8; KEY_LEN]);
#[derive(Clone, Debug)]
pub struct SecretHashDomain(Secret<KEY_LEN>);
#[derive(Clone, Debug)]
pub struct SecretHashDomainNamespace(Secret<KEY_LEN>);

impl HashDomain {
    pub fn zero() -> Self {
        Self([0u8; KEY_LEN])
    }

    pub fn dup(self) -> HashDomainNamespace {
        HashDomainNamespace(self.0)
    }

    pub fn turn_secret(self) -> SecretHashDomain {
        SecretHashDomain(Secret::from_slice(&self.0))
    }

    // TODO: Protocol! Use domain separation to ensure that
    pub fn mix(self, v: &[u8]) -> Result<Self> {
        Ok(Self(hash::hash(&self.0, v).collect::<[u8; KEY_LEN]>()?))
    }

    pub fn mix_secret<const N: usize>(self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(&self.0, v.secret())
    }

    pub fn into_value(self) -> [u8; KEY_LEN] {
        self.0
    }
}

impl HashDomainNamespace {
    pub fn mix(&self, v: &[u8]) -> Result<HashDomain> {
        Ok(HashDomain(
            hash::hash(&self.0, v).collect::<[u8; KEY_LEN]>()?,
        ))
    }

    pub fn mix_secret<const N: usize>(&self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(&self.0, v.secret())
    }
}

impl SecretHashDomain {
    pub fn invoke_primitive(k: &[u8], d: &[u8]) -> Result<SecretHashDomain> {
        let mut r = SecretHashDomain(Secret::zero());
        hash::hash(k, d).to(r.0.secret_mut())?;
        Ok(r)
    }

    pub fn zero() -> Self {
        Self(Secret::zero())
    }

    pub fn dup(self) -> SecretHashDomainNamespace {
        SecretHashDomainNamespace(self.0)
    }

    pub fn danger_from_secret(k: Secret<KEY_LEN>) -> Self {
        Self(k)
    }

    pub fn mix(self, v: &[u8]) -> Result<SecretHashDomain> {
        Self::invoke_primitive(self.0.secret(), v)
    }

    pub fn mix_secret<const N: usize>(self, v: Secret<N>) -> Result<SecretHashDomain> {
        Self::invoke_primitive(self.0.secret(), v.secret())
    }

    pub fn into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }

    pub fn into_secret_slice(mut self, v: &[u8], dst: &[u8]) -> Result<()> {
        hash::hash(v, dst).to(self.0.secret_mut())
    }
}

impl SecretHashDomainNamespace {
    pub fn mix(&self, v: &[u8]) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(self.0.secret(), v)
    }

    pub fn mix_secret<const N: usize>(&self, v: Secret<N>) -> Result<SecretHashDomain> {
        SecretHashDomain::invoke_primitive(self.0.secret(), v.secret())
    }

    // TODO: This entire API is not very nice; we need this for biscuits, but
    // it might be better to extract a special "biscuit"
    // labeled subkey and reinitialize the chain with this
    pub fn danger_into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }
}
