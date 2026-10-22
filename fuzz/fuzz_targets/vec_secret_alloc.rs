#![no_main]

use libfuzzer_sys::fuzz_target;
use rosenpass::internal::secret_memory::alloc::secret_vec;

fuzz_target!(|data: &[u8]| {
    let mut vec = secret_vec();
    vec.extend_from_slice(data);
});
