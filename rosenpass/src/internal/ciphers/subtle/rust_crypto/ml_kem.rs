//! # Rosenpass internal ML-KEM bindings
//!
//! provides bindings to [`ml_kem`] crate which implements ML-KEM (FIPS 203)
//!
//! This is an internal library; no guarantee is made about its API at this point in time.

use crate::internal::cipher_traits::{
    algorithms::{KemMlKem512, kem_ml_kem512::*},
    primitives::{Kem, KemError},
};

use ::ml_kem::kem::{Decapsulate, Encapsulate};
use ::ml_kem::{
    EncapsulationKey, Kem as UpstreamKem, Key, KeyExport, MlKem512 as UpstreamMlKem512,
};
use ml_kem::ExpandedKeyEncoding;

/// ML-KEM-512 (FIPS 203) bindings, implemented using the pure-Rust [`ml_kem`] crate.
///
/// # Examples
///
#[cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
#[cfg_attr(not(feature = "expose_internal_modules"), doc = "```rust,ignore")]
/// use rosenpass::internal::cipher_traits::primitives::Kem;
/// use rosenpass::internal::ciphers::subtle::rust_crypto::ml_kem::MlKem512 as MyKem;
/// use rosenpass::internal::secret_memory::{Secret, Public};
/// use rosenpass::internal::constant_time::compare;
///
/// rosenpass::internal::secret_memory::secret_policy_try_use_memfd_secrets();
///
/// // Recipient generates secret key, transfers pk to sender
/// let mut sk = Secret::<{ MyKem::SK_LEN }>::zero();
/// let mut pk = Public::<{ MyKem::PK_LEN }>::zero();
/// MyKem.keygen(sk.secret_mut(), &mut pk);
///
/// // Sender generates ciphertext and local shared key, sends ciphertext to recipient
/// let mut ct = Public::<{ MyKem::CT_LEN }>::zero();
/// let mut shk_enc = Secret::<{ MyKem::SHK_LEN }>::zero();
/// MyKem.encaps(shk_enc.secret_mut(), &mut ct, &pk);
///
/// // Recipient decapsulates ciphertext
/// let mut shk_dec = Secret::<{ MyKem::SHK_LEN }>::zero();
/// MyKem.decaps(shk_dec.secret_mut(), sk.secret(), &ct);
///
/// // Both parties end up with the same shared key
/// assert!(compare(shk_enc.secret(), shk_dec.secret()) == 0);
/// ```
pub struct MlKem512;

impl Default for MlKem512 {
    fn default() -> Self {
        Self
    }
}

// provide the sizes and the `Kem` trait (implementation of the trait below)
impl KemMlKem512 for MlKem512 {}

// actual implementation of the `Kem` trait
//
// A similar implementation for reference can be found in `crate::internal::oqs::kem_macro`.
impl Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> for MlKem512 {
    fn keygen(&self, sk: &mut [u8; SK_LEN], pk: &mut [u8; PK_LEN]) -> Result<(), KemError> {
        // generate the keypair
        // NOTE: the seed can be obtained via dk.to_seed()
        let (dk, ek) = UpstreamMlKem512::generate_keypair_from_rng(&mut rand::rng());

        // save results
        // about deprecation warning, see: https://github.com/rosenpass/rosenpass/issues/1150
        sk.copy_from_slice(&dk.to_expanded_bytes()); // NOTE: do not use `to_bytes` because that would only yield the seed
        pk.copy_from_slice(&ek.to_bytes());

        // return
        Ok(())
    }

    fn encaps(
        &self,
        shk: &mut [u8; SHK_LEN],
        ct: &mut [u8; CT_LEN],
        pk: &[u8; PK_LEN],
    ) -> Result<(), KemError> {
        // deserialize `pk` to `::ml_kem::EncapsulationKey`
        let ek_bytes: &Key<EncapsulationKey<UpstreamMlKem512>> = pk.into();
        let ek = EncapsulationKey::<UpstreamMlKem512>::new(ek_bytes)
            .map_err(|_| KemError::CanNotDeserializeEncapsulationKey)?;

        // encapsulate
        let (ciphertext, shared_key) = ek.encapsulate_with_rng(&mut rand::rng());

        // save results
        ct.copy_from_slice(&ciphertext);
        shk.copy_from_slice(&shared_key);

        // return
        Ok(())
    }

    fn decaps(
        &self,
        shk: &mut [u8; SHK_LEN],
        sk: &[u8; SK_LEN],
        ct: &[u8; CT_LEN],
    ) -> Result<(), KemError> {
        // deserialize `sk` to `::ml_kem::DecapsulationKey`
        // about deprecation warning, see: https://github.com/rosenpass/rosenpass/issues/1150
        let dk = ::ml_kem::DecapsulationKey::<UpstreamMlKem512>::from_expanded_bytes(sk.into())
            .map_err(|_| KemError::CanNotDeserializeDecapsulationKey)?;

        // decapsulate
        let k = dk.decapsulate(ct.into());

        // save result
        shk.copy_from_slice(&k);

        // return
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn ml_kem_512_one_entire_roundtrip() {
        // keygen
        let (mut sk, mut pk) = ([0u8; SK_LEN], [0u8; PK_LEN]);
        MlKem512.keygen(&mut sk, &mut pk).unwrap();

        // encaps
        let (mut shk_enc, mut ct) = ([0u8; SHK_LEN], [0u8; CT_LEN]);
        MlKem512.encaps(&mut shk_enc, &mut ct, &pk).unwrap();

        // decaps
        let mut shk_dec = [0u8; SHK_LEN];
        MlKem512.decaps(&mut shk_dec, &sk, &ct).unwrap();

        // check
        assert_eq!(shk_enc, shk_dec);
    }

    #[test]
    fn ml_kem_512_implicit_rejection() {
        // keygen
        let (mut sk, mut pk) = ([0u8; SK_LEN], [0u8; PK_LEN]);
        MlKem512.keygen(&mut sk, &mut pk).unwrap();

        // encaps
        let (mut shk_enc, mut ct) = ([0u8; SHK_LEN], [0u8; CT_LEN]);
        MlKem512.encaps(&mut shk_enc, &mut ct, &pk).unwrap();

        // corrupt the ciphertext
        ct[0] ^= 1;

        // decaps
        // NOTE: decapsulation must not fail but must yield a different shared key (implicit rejection)
        let mut shk_dec = [0u8; SHK_LEN];
        MlKem512.decaps(&mut shk_dec, &sk, &ct).unwrap();

        // check
        assert_ne!(shk_enc, shk_dec);
    }
}
