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

pub mod test {
    #[macro_export]
    macro_rules! test_spawn_process_with_policies {
        ($body:block, $($f: expr),*) => {
            $(
                let handle = procspawn::spawn((), |_| {

                $f();

                $body

                });
                handle.join().unwrap();
            )*
            };
        }

    #[macro_export]
    macro_rules! test_spawn_process_provided_policies {
        ($body: block) => {
            $crate::test_spawn_process_with_policies!(
                $body,
                $crate::policy::secret_policy_try_use_memfd_secrets,
                $crate::secret_policy_use_only_malloc_secrets
            );

            #[cfg(target_os = "linux")]
            {
                $crate::test_spawn_process_with_policies!(
                    $body,
                    $crate::policy::secret_policy_use_only_memfd_secrets
                );
            }
        };
    }
}
