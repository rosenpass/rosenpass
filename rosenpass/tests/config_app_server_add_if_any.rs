use rosenpass::cfg;

#[test]
fn config_app_server_add_if_any_example() {
    let mut config = cfg::AppServer::empty();
    config.add_if_any(4000);

    assert!(
        config
            .listen
            .iter()
            .any(|a| format!("{a:?}") == "0.0.0.0:4000")
    );
    assert!(
        config
            .listen
            .iter()
            .any(|a| format!("{a:?}") == "[::]:4000")
    );
}
