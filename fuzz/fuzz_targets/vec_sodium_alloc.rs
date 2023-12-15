#![no_main]

use libfuzzer_sys::fuzz_target;
use rosenpass_sodium::{
    alloc::{Alloc as SodiumAlloc, Vec as SodiumVec},
    init,
};

fuzz_target!(|data: &[u8]| {
    let _ = init();
    let mut vec = SodiumVec::new_in(SodiumAlloc::new());
    vec.extend_from_slice(data);
});
