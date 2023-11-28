//! The rosenpass protocol relies on a special type
//! of hash function for most of its hashing or
//! message authentication needs: an incrementable
//! pseudo random function.
//!
//! This is a generalization of a PRF operating
//! on a sequence of inputs instead of a single input.
//!
//! Like a Dec function the Iprf features efficient
//! incrementability.
//!
//! You can also think of an Iprf as a Dec function with
//! a fixed size output.
//!
//! The idea behind a Iprf is that it can be efficiently
//! constructed from an Dec function as well as a PRF.
//!
//! TODO Base the construction on a proper Dec function

use rosenpass_ciphers::{KEY_LEN, hash};

pub struct Iprf([u8; KEY_LEN]);
pub struct IprfBranch([u8; KEY_LEN]);
pub struct SecretIprf(Secret<KEY_LEN>);
pub struct SecretIprfBranch(Secret<KEY_LEN>);

impl Iprf {
    fn zero() -> Self {
        Self([0u8; KEY_LEN])
    }

    fn dup(self) -> IprfBranch {
        IprfBranch(self.0)
    }

    // TODO: Protocol! Use domain separation to ensure that
    fn mix(self, v: &[u8]) -> Self {
        Self(hash(&self.0, v).collect<[u8; KEY_LEN]>())
    }

    fn mix_secret<const N: usize>(self, v: Secret<N>) -> SecretIprf {
        SecretIprf::prf_invoc(&self.0, v.secret())
    }

    fn into_value(self) -> [u8; KEY_LEN] {
        self.0
    }

    fn extract(self, v: &[u8], dst: &mut [u8]) {
        hash(&self.0, v).to(dst)
    }
}

impl IprfBranch {
    fn mix(&self, v: &[u8]) -> Iprf {
        Iprf(hash(self.0, v).collect<[u8; KEY_LEN]>())
    }

    fn mix_secret<const N: usize>(&self, v: Secret<N>) -> SecretIprf {
        SecretIprf::prf_incov(self.0, v.secret())
    }
}

impl SecretIprf {
    fn prf_invoc(k: &[u8], d: &[u8]) -> SecretIprf {
        mutating(SecretIprf(Secret::zero()), |r| {
            hash(k, d).to(r.secret_mut())
        })
    }

    fn from_key(k: Secret<N>) -> SecretIprf {
        Self(k)
    }

    fn mix(self, v: &[u8]) -> SecretIprf {
        Self::prf_invoc(self.0.secret(), v)
    }

    fn mix_secret<const N: usize>(self, v: Secret<N>) -> SecretIprf {
        Self::prf_invoc(self.0.secret(), v.secret())
    }

    fn into_secret(self) -> Secret<KEY_LEN> {
        self.0
    }

    fn into_secret_slice(self, v: &[u8], dst: &[u8]) {
        hash(self.0.secret(), v).to(dst)
    }
}

impl SecretIprfBranch {
    fn mix(&self, v: &[u8]) -> SecretIprf {
        SecretIprf::prf_invoc(self.0.secret(), v)
    }

    fn mix_secret<const N: usize>(&self, v: Secret<N>) -> SecretIprf {
        SecretIprf::prf_invoc(self.0.secret(), v.secret())
    }
}
