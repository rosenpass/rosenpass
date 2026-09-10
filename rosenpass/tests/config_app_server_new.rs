use rosenpass::cfg;

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    assert_eq!(
        cfg::AppServer::empty(),
        cfg::AppServer::new(None)
    );
    assert_eq!(
        cfg::AppServer::empty(),
        cfg::AppServer::default()
    );

    assert_eq!(
        cfg::AppServer::from_sk_pk(sk, pk),
        cfg::AppServer::new(Some(cfg::Keypair::new(pk, sk)))
    );

    let mut v = cfg::AppServer::empty();
    v.keypair = Some(cfg::Keypair::new(pk, sk));
    assert_eq!(cfg::AppServer::from_sk_pk(sk, pk), v);
}
