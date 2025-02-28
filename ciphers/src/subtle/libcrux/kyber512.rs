use libcrux_ml_kem::kyber512;

use rand::RngCore;

use rosenpass_cipher_traits::algorithms::kem_kyber512::*;
use rosenpass_cipher_traits::primitives::{Kem, KemError};

pub struct Kyber512;

impl Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> for Kyber512 {
    fn keygen(&self, sk: &mut [u8; SK_LEN], pk: &mut [u8; PK_LEN]) -> Result<(), KemError> {
        let mut randomness = [0u8; libcrux_ml_kem::KEY_GENERATION_SEED_SIZE];
        rand::thread_rng().fill_bytes(&mut randomness);

        let key_pair = kyber512::generate_key_pair(randomness);

        let new_sk: &[u8; SK_LEN] = key_pair.sk();
        let new_pk: &[u8; PK_LEN] = key_pair.pk();

        sk.clone_from_slice(new_sk);
        pk.clone_from_slice(new_pk);

        Ok(())
    }

    fn encaps(
        &self,
        shk: &mut [u8; SHK_LEN],
        ct: &mut [u8; CT_LEN],
        pk: &[u8; PK_LEN],
    ) -> Result<(), KemError> {
        let mut randomness = [0u8; libcrux_ml_kem::SHARED_SECRET_SIZE];
        rand::thread_rng().fill_bytes(&mut randomness);

        let (new_ct, new_shk) = kyber512::encapsulate(&pk.into(), randomness);
        let new_ct: &[u8; CT_LEN] = new_ct.as_slice();

        shk.clone_from_slice(&new_shk);
        ct.clone_from_slice(new_ct);

        Ok(())
    }

    fn decaps(
        &self,
        shk: &mut [u8; SHK_LEN],
        sk: &[u8; SK_LEN],
        ct: &[u8; CT_LEN],
    ) -> Result<(), KemError> {
        let new_shk: [u8; SHK_LEN] = kyber512::decapsulate(&sk.into(), &ct.into());
        shk.clone_from(&new_shk);
        Ok(())
    }
}

impl Default for Kyber512 {
    fn default() -> Self {
        Self
    }
}

impl KemKyber512 for Kyber512 {}
