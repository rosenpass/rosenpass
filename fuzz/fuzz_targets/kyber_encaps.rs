#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::EphemeralKem;

use rosenpass_to::to;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Input {
    pub pk: [u8; EphemeralKem::PK_LEN],
}

fuzz_target!(|input: Input| {
    if input.len() < 32 {
        return;
    }

    let input = Kyber768Input::from(input);

    let mut ciphertext = [0u8; KYBER_CIPHERTEXT_LEN];
    let mut shared_secret = [0u8; 32];

    to(
        EphemeralKem::encaps(&input.pk, &mut ciphertext, &mut shared_secret),
        &mut ciphertext,
    );
});
