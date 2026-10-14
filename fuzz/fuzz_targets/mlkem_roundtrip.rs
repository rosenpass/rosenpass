#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use ml_kem::{ExpandedKeyEncoding, KeyExport};
use rosenpass::internal::cipher_traits::algorithms::kem_classic_mceliece460896::SHK_LEN;
// use ml_kem::Kem;
use rosenpass::internal::cipher_traits::primitives::Kem;
use rosenpass::internal::ciphers::EphemeralKem;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Input {
    /// the seed to generate a public key (encapsulation key)
    pub pk_seed: [u8; 64],
}

fuzz_target!(|input: Input| {
    // derive keypair from seed
    let sk = ml_kem::DecapsulationKey512::from_seed(input.pk_seed.into());
    let pk = sk.encapsulation_key();
    let sk: [u8; EphemeralKem::SK_LEN] = sk.to_expanded_bytes().into();
    let pk: [u8; EphemeralKem::PK_LEN] = pk.to_bytes().into();

    // encaps
    let (mut shk_enc, mut ct) = ([0u8; EphemeralKem::SHK_LEN], [0u8; EphemeralKem::CT_LEN]);
    EphemeralKem::MlKem512
        .encaps(&mut shk_enc, &mut ct, &pk)
        .unwrap();

    // decaps
    let mut shk_dec = [0u8; SHK_LEN];
    EphemeralKem::MlKem512
        .decaps(&mut shk_dec, &sk, &ct)
        .unwrap();

    // check
    assert_eq!(shk_enc, shk_dec);
});
