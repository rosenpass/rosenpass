#![no_main]
use libfuzzer_sys::fuzz_target;
use ciphers::blake2b;
use rosenpass_to::to;

#[derive(arbitrary::Arbitrary, Debug)]
pub struct Blake2bInput {
    pub key: [u8; 32],
    pub data: Box<[u8]>,
}

impl From<&[u8]> for Blake2bInput {
    fn from(input: &[u8]) -> Self {
        let key = <[u8; 32]>::try_from(&input[..32]).unwrap();
        let data = input[32..].to_vec().into_boxed_slice();
        Blake2bInput { key, data }
    }
}

fuzz_target!(|input: &[u8]| {
    if input.len() < 32 {
        return;
    }

    let mut input = Blake2bInput::from(input);
    let mut out = [0u8; 32];
    
    to(&mut out, blake2b::hash(&input.key, &input.data)).unwrap();
});
