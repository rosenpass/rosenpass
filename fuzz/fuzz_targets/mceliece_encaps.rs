#![no_main]
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;

fuzz_target!(|input: [u8; StaticKem::PK_LEN]| {
    let mut ciphertext = [0u8; 188];
    let mut shared_secret = [0u8; 32];

    // We expect errors while fuzzing therefore we do not check the result.
    let _ = StaticKem::encaps(&mut shared_secret, &mut ciphertext, &input);
});
