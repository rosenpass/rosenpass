//! This module only contains [`EphemeralKemChoice`] – see its documentation.

use super::rust_crypto::ml_kem::MlKem512;
use crate::internal::cipher_traits::algorithms::kem_ml_kem512;
use crate::internal::cipher_traits::primitives::{Kem, KemError};
use crate::internal::oqs::Kyber512;

/// choice of the  ephemeral key encapsulation mechanism to use in the Rosenpass protocol
///
/// See the ephemeral keypairs `eski`/`epki` in the whitepaper.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EphemeralKemChoice {
    /// Kyber512 (NIST competition, round 3)
    ///
    /// This was the original choice in early Rosenpass version (protocol v02) when ML-KEM had not been standardized back then.
    Kyber512Round3,

    /// ML-KEM-512 (FIPS 203)
    ///
    /// newer choice since protocol version v03
    MlKem512,
}

impl EphemeralKemChoice {
    /// The secret key length of the ephemeral KEM (same for both variants).
    pub const SK_LEN: usize = kem_ml_kem512::SK_LEN;
    /// The public key length of the ephemeral KEM (same for both variants).
    pub const PK_LEN: usize = kem_ml_kem512::PK_LEN;
    /// The ciphertext length of the ephemeral KEM (same for both variants).
    pub const CT_LEN: usize = kem_ml_kem512::CT_LEN;
    /// The shared key length of the ephemeral KEM (same for both variants).
    pub const SHK_LEN: usize = kem_ml_kem512::SHK_LEN;

    /// identifier used in the protocol's hash domain separation strings
    ///
    /// also see implementation of [`crate::hash_domains::protocol`]
    pub const fn protocol_string_kem_id(&self) -> &'static str {
        match self {
            EphemeralKemChoice::Kyber512Round3 => "Kyber512",
            EphemeralKemChoice::MlKem512 => "ML-KEM-512",
        }
    }
}

impl
    Kem<
        { EphemeralKemChoice::SK_LEN },
        { EphemeralKemChoice::PK_LEN },
        { EphemeralKemChoice::CT_LEN },
        { EphemeralKemChoice::SHK_LEN },
    > for EphemeralKemChoice
{
    fn keygen(
        &self,
        sk: &mut [u8; EphemeralKemChoice::SK_LEN],
        pk: &mut [u8; EphemeralKemChoice::PK_LEN],
    ) -> Result<(), KemError> {
        match self {
            EphemeralKemChoice::Kyber512Round3 => Kyber512.keygen(sk, pk),
            EphemeralKemChoice::MlKem512 => MlKem512.keygen(sk, pk),
        }
    }

    fn encaps(
        &self,
        shk: &mut [u8; EphemeralKemChoice::SHK_LEN],
        ct: &mut [u8; EphemeralKemChoice::CT_LEN],
        pk: &[u8; EphemeralKemChoice::PK_LEN],
    ) -> Result<(), KemError> {
        match self {
            EphemeralKemChoice::Kyber512Round3 => Kyber512.encaps(shk, ct, pk),
            EphemeralKemChoice::MlKem512 => MlKem512.encaps(shk, ct, pk),
        }
    }

    fn decaps(
        &self,
        shk: &mut [u8; EphemeralKemChoice::SHK_LEN],
        sk: &[u8; EphemeralKemChoice::SK_LEN],
        ct: &[u8; EphemeralKemChoice::CT_LEN],
    ) -> Result<(), KemError> {
        match self {
            EphemeralKemChoice::Kyber512Round3 => Kyber512.decaps(shk, sk, ct),
            EphemeralKemChoice::MlKem512 => MlKem512.decaps(shk, sk, ct),
        }
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn ml_kem_512_dispatch_through_ephemeral_kem_enum() {
        use super::EphemeralKemChoice;
        use super::Kem; // Kem trait re-exported by super

        // keygen
        let (mut sk, mut pk) = (
            [0u8; EphemeralKemChoice::SK_LEN],
            [0u8; EphemeralKemChoice::PK_LEN],
        );
        EphemeralKemChoice::MlKem512
            .keygen(&mut sk, &mut pk)
            .unwrap();

        // encaps
        let (mut shk_enc, mut ct) = (
            [0u8; EphemeralKemChoice::SHK_LEN],
            [0u8; EphemeralKemChoice::CT_LEN],
        );
        EphemeralKemChoice::MlKem512
            .encaps(&mut shk_enc, &mut ct, &pk)
            .unwrap();

        // decaps
        let mut shk_dec = [0u8; EphemeralKemChoice::SHK_LEN];
        EphemeralKemChoice::MlKem512
            .decaps(&mut shk_dec, &sk, &ct)
            .unwrap();

        // check
        assert_eq!(shk_enc, shk_dec);
    }

    #[test]
    fn kyber512_dispatch_still_works() {
        use super::EphemeralKemChoice;
        use super::Kem; // Kem trait re-exported by super

        // keygen
        let (mut sk, mut pk) = (
            [0u8; EphemeralKemChoice::SK_LEN],
            [0u8; EphemeralKemChoice::PK_LEN],
        );
        EphemeralKemChoice::Kyber512Round3
            .keygen(&mut sk, &mut pk)
            .unwrap();

        // encaps
        let (mut shk_enc, mut ct) = (
            [0u8; EphemeralKemChoice::SHK_LEN],
            [0u8; EphemeralKemChoice::CT_LEN],
        );
        EphemeralKemChoice::Kyber512Round3
            .encaps(&mut shk_enc, &mut ct, &pk)
            .unwrap();

        // decaps
        let mut shk_dec = [0u8; EphemeralKemChoice::SHK_LEN];
        EphemeralKemChoice::Kyber512Round3
            .decaps(&mut shk_dec, &sk, &ct)
            .unwrap();

        // check
        assert_eq!(shk_enc, shk_dec);
    }
}
