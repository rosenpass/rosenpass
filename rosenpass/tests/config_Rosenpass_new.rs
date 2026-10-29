use rosenpass::config::{Keypair, RosenpassConfig};

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    assert_eq!(
        RosenpassConfig::new_empty(),
        RosenpassConfig::new_minimal(None)
    );
    assert_eq!(RosenpassConfig::new_empty(), RosenpassConfig::default());

    assert_eq!(
        RosenpassConfig::from_sk_pk(sk, pk),
        RosenpassConfig::new_minimal(Some(Keypair::new_from_files(pk, sk)))
    );

    let mut v = RosenpassConfig::new_empty();
    v.our_keypair = Some(Keypair::new_from_files(pk, sk));
    assert_eq!(RosenpassConfig::from_sk_pk(sk, pk), v);
}
