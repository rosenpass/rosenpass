#![no_main]

use libfuzzer_sys::fuzz_target;
use rosenpass_secret_memory::alloc::secret_box;

fuzz_target!(|data: &[u8]| {
    let _ = secret_box(data);
});
