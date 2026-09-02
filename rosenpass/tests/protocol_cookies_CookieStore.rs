#[test]
fn cookie_store_demo() {
    use rosenpass::internal::util::time::Timebase;
    use rosenpass::protocol::{basic_types::SymKey, cookies::CookieStore, timing::BCE};

    rosenpass::internal::secret_memory::secret_policy_try_use_memfd_secrets();

    let fixed_secret = SymKey::random();
    let timebase = Timebase::default();

    let mut store = CookieStore::<32>::new();
    assert_ne!(store.value.secret(), SymKey::zero().secret());
    assert_eq!(store.created_at, BCE);

    let time_before_call = timebase.now();
    store.update(&timebase, fixed_secret.secret());
    assert_eq!(store.value.secret(), fixed_secret.secret());
    assert!(store.created_at <= timebase.now());
    assert!(store.created_at >= time_before_call);

    // Same as new()
    store.erase();
    assert_ne!(store.value.secret(), SymKey::zero().secret());
    assert_eq!(store.created_at, BCE);

    let secret_before_call = store.value.clone();
    let time_before_call = timebase.now();
    store.randomize(&timebase);
    assert_ne!(store.value.secret(), secret_before_call.secret());
    assert!(store.created_at <= timebase.now());
    assert!(store.created_at >= time_before_call);
}
