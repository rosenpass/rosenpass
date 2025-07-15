#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_cipher_traits::primitives::KeyedHashTo;
use rosenpass_ciphers::subtle::blake2b;
use rosenpass_to::to;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Blake2b {
    pub key: [u8; 32],
    pub data: Box<[u8]>,
}

fuzz_target!(|input: Blake2b| {
    let mut out = [0u8; 32];

    to(
        blake2b::Blake2b::keyed_hash_to(&input.key, &input.data),
        &mut out,
    );
});
