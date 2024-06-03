#![no_main]

use libfuzzer_sys::fuzz_target;
use rosenpass_secret_memory::alloc::secret_box;
use rosenpass_secret_memory::policy::*;
use std::sync::Once;

static ONCE: Once = Once::new();

fuzz_target!(|data: &[u8]| {
    ONCE.call_once(secret_policy_try_use_memfd_secrets);
    let _ = secret_box(data);
});
