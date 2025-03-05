#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::primitives::Aead as _;
use rosenpass_ciphers::Aead;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Input {
    pub key: [u8; 32],
    pub nonce: [u8; 12],
    pub ad: Box<[u8]>,
    pub plaintext: Box<[u8]>,
}

fuzz_target!(|input: Input| {
    let mut ciphertext = vec![0u8; input.plaintext.len() + 16];

    Aead.encrypt(
        ciphertext.as_mut_slice(),
        &input.key,
        &input.nonce,
        &input.ad,
        &input.plaintext,
    )
    .unwrap();
});
