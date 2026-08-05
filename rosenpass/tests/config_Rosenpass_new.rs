use rosenpass::config::{self, Rosenpass, rosenpass_keypair::RosenpassKeypair};

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    assert_eq!(Rosenpass::empty(), Rosenpass::new(None));
    assert_eq!(Rosenpass::empty(), Rosenpass::default());

    assert_eq!(
        Rosenpass::from_sk_pk(sk, pk),
        Rosenpass::new(Some(RosenpassKeypair::new(pk, sk)))
    );

    let mut v = Rosenpass::empty();
    v.keypair = Some(RosenpassKeypair::new(pk, sk));
    assert_eq!(Rosenpass::from_sk_pk(sk, pk), v);
}
