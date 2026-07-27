//! This crates the `memsec` and `memfdsec` allocators from the [memsec] crate to be used for
//! allocations of memory on which [Secrects](crate::Secret) are stored. This, however, requires
//! that an allocator is chosen before [Secret](crate::Secret) is used the first time.
//! This module provides functionality for just that.

/// This function sets the `memfdsec` allocator as the default in case it is supported by
/// the target and uses the `memsec` allocator otherwise.
///
/// At the time of writing, the `memfdsec` allocator is just supported on linux targets.
pub fn secret_policy_try_use_memfd_secrets() {
    let alloc_type = {
        #[cfg(target_os = "linux")]
        {
            if crate::alloc::memsec::memfdsec::memfdsec_box_try(0u8).is_ok() {
                crate::alloc::SecretAllocType::MemsecMemfdSec
            } else {
                crate::alloc::SecretAllocType::MemsecMalloc
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            crate::alloc::SecretAllocType::MemsecMalloc
        }
    };
    assert_eq!(
        alloc_type,
        crate::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

/// This functions sets the `memfdsec` allocator as the default. At the time of writing
/// this is only supported on Linux targets.
#[cfg(target_os = "linux")]
pub fn secret_policy_use_only_memfd_secrets() {
    let alloc_type = crate::alloc::SecretAllocType::MemsecMemfdSec;

    assert_eq!(
        alloc_type,
        crate::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

/// This function sets the `memsec` allocator as the default. It is supported on all targets.
pub fn secret_policy_use_only_malloc_secrets() {
    let alloc_type = crate::alloc::SecretAllocType::MemsecMalloc;
    assert_eq!(
        alloc_type,
        crate::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

#[cfg(test)]
pub mod test {
    use std::sync::{Mutex, OnceLock};

    const POLICY_INDEX_ENV: &str = "ROSENPASS_SECRET_MEMORY_TEST_POLICY_INDEX";

    pub fn policy_test_spawn_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    pub fn child_policy_index(policy_count: usize) -> Option<usize> {
        let index = std::env::var(POLICY_INDEX_ENV).ok()?;
        let index = index
            .parse::<usize>()
            .expect("policy index must be a valid integer");
        assert!(
            index < policy_count,
            "policy index {index} out of range for {policy_count} policies"
        );
        Some(index)
    }

    pub fn spawn_current_test_with_policy(policy_index: usize) {
        let current_test = std::thread::current()
            .name()
            .expect("test thread should be named by libtest")
            .to_owned();
        let current_exe = std::env::current_exe().expect("test binary path should be available");
        let output = std::process::Command::new(current_exe)
            .arg("--exact")
            .arg(current_test)
            .env(POLICY_INDEX_ENV, policy_index.to_string())
            .output()
            .expect("failed to spawn child test process");

        if !output.status.success() {
            eprintln!("{}", String::from_utf8_lossy(&output.stdout));
            eprintln!("{}", String::from_utf8_lossy(&output.stderr));
            panic!(
                "child test process failed for policy index {policy_index}: {}",
                output.status
            );
        }
    }

    #[macro_export]
    macro_rules! test_spawn_process_with_policies {
        ($body:block, $($f: expr),* $(,)?) => {
            {
                let policies: &[fn()] = &[$($f),*];
                if let Some(policy_index) = $crate::policy::test::child_policy_index(policies.len()) {
                    policies[policy_index]();
                    $body
                } else {
                    let _guard = $crate::policy::test::policy_test_spawn_lock()
                        .lock()
                        .expect("policy test spawn lock should not be poisoned");
                    for policy_index in 0..policies.len() {
                        $crate::policy::test::spawn_current_test_with_policy(policy_index);
                    }
                }
            }
            };
        }

    #[macro_export]
    macro_rules! test_spawn_process_provided_policies {
        ($body: block) => {
            #[cfg(target_os = "linux")]
            $crate::test_spawn_process_with_policies!(
                $body,
                $crate::policy::secret_policy_try_use_memfd_secrets,
                $crate::secret_policy_use_only_malloc_secrets,
                $crate::policy::secret_policy_use_only_memfd_secrets
            );

            #[cfg(not(target_os = "linux"))]
            $crate::test_spawn_process_with_policies!(
                $body,
                $crate::policy::secret_policy_try_use_memfd_secrets,
                $crate::secret_policy_use_only_malloc_secrets
            );
        };
    }
}
