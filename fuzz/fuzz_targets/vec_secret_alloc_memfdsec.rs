#![no_main]

use std::sync::Once;

use libfuzzer_sys::fuzz_target;
use rosenpass_secret_memory::alloc::secret_vec;
use rosenpass_secret_memory::policy::*;

static ONCE: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    ONCE.call_once(secret_policy_use_only_memfd_secrets);
    let mut vec = secret_vec();
    vec.extend_from_slice(data);
});
