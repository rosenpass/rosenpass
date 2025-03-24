#![no_main]
use libfuzzer_sys::fuzz_target;
use ciphers::ephemeral_kem::EphemeralKem;
use rosenpass_to::to;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Input {
    pub pk: [u8; EphemeralKem::PK_LEN],
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 32 {
        return;
    }
    let input = Kyber768Input::from(input);
    let mut shared_secret = [0u8; 32];
    let mut ciphertext = [0u8; KYBER_CIPHERTEXT_BYTES];
    
    to(&mut shared_secret, to(&mut ciphertext, EphemeralKem::encaps(&input.pk))).unwrap();
});
