pub fn secret_policy_try_use_memfd_secrets() {
    let alloc_type = {
        #[cfg(target_os = "linux")]
        {
            if crate::alloc::memsec::memfdsec::memfdsec_box_try(()).is_ok() {
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

#[cfg(target_os = "linux")]
pub fn secret_policy_use_only_memfd_secrets() {
    let alloc_type = crate::alloc::SecretAllocType::MemsecMemfdSec;

    assert_eq!(
        alloc_type,
        crate::alloc::get_or_init_secret_alloc_type(alloc_type)
    );

    log::info!("Secrets will be allocated using {:?}", alloc_type);
}

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
