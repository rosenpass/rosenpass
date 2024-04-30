#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass_ciphers::subtle::blake2b;
use rosenpass_to::To;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Blake2b {
    pub key: [u8; 32],
    pub data: Box<[u8]>,
}

fuzz_target!(|input: Blake2b| {
    let mut out = [0u8; 32];

    blake2b::hash(&input.key, &input.data).to(&mut out).unwrap();
});
