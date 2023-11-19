#![no_main]
extern crate arbitrary;
extern crate rosenpass;

use libfuzzer_sys::fuzz_target;

use rosenpass::sodium::mac_into;
use rosenpass_sodium::init as sodium_init;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Blake2b {
    pub key: [u8; 32],
    pub data: Box<[u8]>,
}

fuzz_target!(|input: Blake2b| {
    sodium_init().unwrap();

    let mut out = [0u8; 32];

    mac_into(&mut out, &input.key, &input.data).unwrap();
});
