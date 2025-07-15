#![no_main]
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;

use rosenpass_to::to;

fuzz_target!(|input: [u8; StaticKem::PK_LEN]| {
    let mut ciphertext = [0u8; StaticKem::CT_LEN];
    let mut shared_secret = [0u8; StaticKem::SHK_LEN];

    // We expect errors while fuzzing therefore we do not check the result.
    let _ = to(
        StaticKem.encaps(&mut shared_secret, &mut ciphertext, &input),
        &mut ciphertext,
    );
});
