use rosenpass::config::{self, RosenpassConfig, rosenpass_keypair::RosenpassKeypair};

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    assert_eq!(RosenpassConfig::empty(), RosenpassConfig::new(None));
    assert_eq!(RosenpassConfig::empty(), RosenpassConfig::default());

    assert_eq!(
        RosenpassConfig::from_sk_pk(sk, pk),
        RosenpassConfig::new(Some(RosenpassKeypair::new(pk, sk)))
    );

    let mut v = RosenpassConfig::empty();
    v.keypair = Some(RosenpassKeypair::new(pk, sk));
    assert_eq!(RosenpassConfig::from_sk_pk(sk, pk), v);
}
