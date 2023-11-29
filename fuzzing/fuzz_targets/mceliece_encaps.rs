#![no_main]
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass::pqkem::{StaticKEM, KEM};

fuzz_target!(|input: &[u8]| {
    let mut ciphertext = [0u8; 188];
    let mut shared_secret = [0u8; 32];

    // We expect errors while fuzzing therefore we do not check the result.
    let _ = StaticKEM::encaps(&mut shared_secret, &mut ciphertext, input);
});
