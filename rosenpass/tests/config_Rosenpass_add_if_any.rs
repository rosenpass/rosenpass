use rosenpass::config::Rosenpass;

#[test]
fn config_Rosenpass_add_if_any_example() {
    let mut v = Rosenpass::empty();
    v.add_if_any(4000);

    assert!(v.listen.iter().any(|a| format!("{a:?}") == "0.0.0.0:4000"));
    assert!(v.listen.iter().any(|a| format!("{a:?}") == "[::]:4000"));
}
