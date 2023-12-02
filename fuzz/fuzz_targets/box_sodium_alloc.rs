#![no_main]

use libfuzzer_sys::fuzz_target;
use rosenpass_sodium::{
    alloc::{Alloc as SodiumAlloc, Box as SodiumBox},
    init,
};

fuzz_target!(|data: &[u8]| {
    let _ = init();
    let _ = SodiumBox::new_in(data, SodiumAlloc::new());
});
