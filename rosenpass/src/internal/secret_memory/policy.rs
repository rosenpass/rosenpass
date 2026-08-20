//! This creates the `memsec` and `memfdsec` allocators from the [memsec] crate to be used for
//! allocations of memory on which [Secrects](super::Secret) are stored. This, however, requires
//! that an allocator is chosen before [`Secret`](super::Secret) is used the first time.
//! This module provides functionality for just that.

/// This function sets the `memfdsec` allocator as the default in case it is supported by
/// the target and uses the `memsec` allocator otherwise.
///
/// At the time of writing, the `memfdsec` allocator is just supported on linux targets.
pub fn secret_policy_try_use_memfd_secrets() {
    let alloc_type = {
        #[cfg(target_os = "linux")]
        {
            if super::alloc::memsec::memfdsec::memfdsec_box_try(0u8).is_ok() {
                super::alloc::SecretAllocType::MemsecMemfdSec
            } else {
                super::alloc::SecretAllocType::MemsecMalloc
            }
        }

        #[cfg(not(target_os = "linux"))]
        {
            super::alloc::SecretAllocType::MemsecMalloc
        }
    };
    assert_eq!(
        alloc_type,
        super::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

/// This functions sets the `memfdsec` allocator as the default. At the time of writing
/// this is only supported on Linux targets.
#[cfg(target_os = "linux")]
pub fn secret_policy_use_only_memfd_secrets() {
    let alloc_type = super::alloc::SecretAllocType::MemsecMemfdSec;

    assert_eq!(
        alloc_type,
        super::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

/// This function sets the `memsec` allocator as the default. It is supported on all targets.
pub fn secret_policy_use_only_malloc_secrets() {
    let alloc_type = super::alloc::SecretAllocType::MemsecMalloc;
    assert_eq!(
        alloc_type,
        super::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

pub mod test {
    #[allow(unused_macros)]
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
    pub(crate) use test_spawn_process_with_policies;

    #[allow(unused_macros)]
    macro_rules! test_spawn_process_provided_policies {
        ($body: block) => {
            $crate::internal::secret_memory::policy::test::test_spawn_process_with_policies!(
                $body,
                $crate::internal::secret_memory::policy::secret_policy_try_use_memfd_secrets,
                $crate::internal::secret_memory::secret_policy_use_only_malloc_secrets
            );

            #[cfg(target_os = "linux")]
            {
                $crate::internal::secret_memory::policy::test::test_spawn_process_with_policies!(
                    $body,
                    $crate::internal::secret_memory::policy::secret_policy_use_only_memfd_secrets
                );
            }
        };
    }
    pub(crate) use test_spawn_process_provided_policies;
}
