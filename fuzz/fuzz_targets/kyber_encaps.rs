#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::EphemeralKem;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Input {
    pub pk: [u8; EphemeralKem::PK_LEN],
}

fuzz_target!(|input: Input| {
    let mut ciphertext = [0u8; EphemeralKem::CT_LEN];
    let mut shared_secret = [0u8; EphemeralKem::SHK_LEN];

    EphemeralKem
        .encaps(&mut shared_secret, &mut ciphertext, &input.pk)
        .unwrap();
});
