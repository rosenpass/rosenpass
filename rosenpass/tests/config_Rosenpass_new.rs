use rosenpass::config;

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    assert_eq!(
        config::RosenpassCfg::empty(),
        config::RosenpassCfg::new(None)
    );
    assert_eq!(
        config::RosenpassCfg::empty(),
        config::RosenpassCfg::default()
    );

    assert_eq!(
        config::RosenpassCfg::from_sk_pk(sk, pk),
        config::RosenpassCfg::new(Some(config::RosenpassKeypair::new(pk, sk)))
    );

    let mut v = config::RosenpassCfg::empty();
    v.keypair = Some(config::RosenpassKeypair::new(pk, sk));
    assert_eq!(config::RosenpassCfg::from_sk_pk(sk, pk), v);
}
