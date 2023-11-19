#![no_main]
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass::pqkem::{StaticKEM, KEM};

fuzz_target!(|input: &[u8]| {
    let mut ciphertext = [0u8; 188];
    let mut shared_secret = [0u8; 32];

    StaticKEM::encaps(&mut shared_secret, &mut ciphertext, input).unwrap();
});
