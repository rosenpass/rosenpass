#![no_main]
extern crate rosenpass;
extern crate arbitrary;

use libfuzzer_sys::fuzz_target;

use rosenpass::sodium::{sodium_init,mac_into};

#[derive(arbitrary::Arbitrary,Debug)]
pub struct Blake2b {
    pub key: [u8; 32],
    pub data: Box<[u8]>
}

fuzz_target!(|input: Blake2b| {
    sodium_init().unwrap();

    let mut out = [0u8;32];

    mac_into(&mut out, &input.key, &input.data).unwrap();
});
