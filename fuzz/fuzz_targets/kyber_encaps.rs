#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::EphemeralKem;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Input {
    pub pk: [u8; 800],
}

fuzz_target!(|input: Input| {
    let mut ciphertext = [0u8; 768];
    let mut shared_secret = [0u8; 32];

    EphemeralKem::encaps(&mut shared_secret, &mut ciphertext, &input.pk).unwrap();
});
