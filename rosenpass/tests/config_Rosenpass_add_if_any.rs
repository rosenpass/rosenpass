use rosenpass::config::RosenpassConfig;

#[test]
fn config_rosenpass_add_if_any_example() {
    let mut v = RosenpassConfig::new_empty();
    v.add_if_any(4000);

    assert!(
        v.our_listen_addresses
            .iter()
            .any(|a| format!("{a:?}") == "0.0.0.0:4000")
    );
    assert!(
        v.our_listen_addresses
            .iter()
            .any(|a| format!("{a:?}") == "[::]:4000")
    );
}
