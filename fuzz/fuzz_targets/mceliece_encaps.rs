#![no_main]
use libfuzzer_sys::fuzz_target;
use ciphers::static_kem::StaticKem;
use rosenpass_to::to;

fuzz_target!(|input: &[u8]| {
    let mut shared_secret = [0u8; 32];
    let mut ciphertext = [0u8; 256];
    
    let _ = to(&mut shared_secret, to(&mut ciphertext, StaticKem::encaps(input)));
    
    // We expect errors while fuzzing therefore we do not check the result.
});
