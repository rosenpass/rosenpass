#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;
#[cfg(not(feature = "experiment_sha3"))]
use rosenpass_ciphers::subtle::blake2b;
use rosenpass_to::To;
#[cfg(not(feature = "experiment_sha3"))]
#[derive(arbitrary::Arbitrary, Debug)]
pub struct Blake2b {
    pub key: [u8; 32],
    pub data: Box<[u8]>,
}
#[cfg(not(feature = "experiment_sha3"))]
fuzz_target!(|input: Blake2b| {
    let mut out = [0u8; 32];

    blake2b::hash(&input.key, &input.data).to(&mut out).unwrap();
});
