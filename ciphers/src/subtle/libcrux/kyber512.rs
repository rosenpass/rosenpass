//! Implementation of the [`KemKyber512`] trait based on the [`libcrux_ml_kem`] crate.

use libcrux_ml_kem::kyber512;
use rand::RngCore;

use rosenpass_cipher_traits::algorithms::KemKyber512;
use rosenpass_cipher_traits::primitives::{Kem, KemError};

pub use rosenpass_cipher_traits::algorithms::kem_kyber512::{CT_LEN, PK_LEN, SHK_LEN, SK_LEN};

/// An implementation of the Kyber512 KEM based on libcrux
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

#[cfg(test)]
mod equivalence_tests {
    use super::*;

    // Test that libcrux and OQS produce the same results
    #[test]
    fn proptest_equivalence_libcrux_oqs() {
        use rosenpass_oqs::Kyber512 as OqsKyber512;

        let (mut sk1, mut pk1) = ([0; SK_LEN], [0; PK_LEN]);
        let (mut sk2, mut pk2) = ([0; SK_LEN], [0; PK_LEN]);

        let mut ct_left = [0; CT_LEN];
        let mut ct_right = [0; CT_LEN];

        let mut shk_enc_left = [0; SHK_LEN];
        let mut shk_enc_right = [0; SHK_LEN];

        // naming schema: shk_dec_{encapsing lib}_{decapsing lib}
        // should be the same if the encapsing lib was the same.
        let mut shk_dec_left_left = [0; SHK_LEN];
        let mut shk_dec_left_right = [0; SHK_LEN];
        let mut shk_dec_right_left = [0; SHK_LEN];
        let mut shk_dec_right_right = [0; SHK_LEN];

        for _ in 0..1000 {
            let sk1 = &mut sk1;
            let pk1 = &mut pk1;
            let sk2 = &mut sk2;
            let pk2 = &mut pk2;

            let ct_left = &mut ct_left;
            let ct_right = &mut ct_right;

            let shk_enc_left = &mut shk_enc_left;
            let shk_enc_right = &mut shk_enc_right;

            let shk_dec_left_left = &mut shk_dec_left_left;
            let shk_dec_left_right = &mut shk_dec_left_right;
            let shk_dec_right_left = &mut shk_dec_right_left;
            let shk_dec_right_right = &mut shk_dec_right_right;

            Kyber512.keygen(sk1, pk1).unwrap();
            Kyber512.keygen(sk2, pk2).unwrap();

            Kyber512.encaps(shk_enc_left, ct_left, pk2).unwrap();
            OqsKyber512.encaps(shk_enc_right, ct_right, pk2).unwrap();

            Kyber512.decaps(shk_dec_left_left, sk2, ct_left).unwrap();
            Kyber512.decaps(shk_dec_right_left, sk2, ct_right).unwrap();

            OqsKyber512
                .decaps(shk_dec_left_right, sk2, ct_left)
                .unwrap();
            OqsKyber512
                .decaps(shk_dec_right_right, sk2, ct_right)
                .unwrap();

            assert_eq!(shk_enc_left, shk_dec_left_left);
            assert_eq!(shk_enc_left, shk_dec_left_right);

            assert_eq!(shk_enc_right, shk_dec_right_left);
            assert_eq!(shk_enc_right, shk_dec_right_right);
        }
    }
}
