use rosenpass::cfg;

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    assert_eq!(
        cfg::RosenpassCfg::empty(),
        cfg::RosenpassCfg::new(None)
    );
    assert_eq!(
        cfg::RosenpassCfg::empty(),
        cfg::RosenpassCfg::default()
    );

    assert_eq!(
        cfg::RosenpassCfg::from_sk_pk(sk, pk),
        cfg::RosenpassCfg::new(Some(cfg::RosenpassKeypair::new(pk, sk)))
    );

    let mut v = cfg::RosenpassCfg::empty();
    v.keypair = Some(cfg::RosenpassKeypair::new(pk, sk));
    assert_eq!(cfg::RosenpassCfg::from_sk_pk(sk, pk), v);
}
