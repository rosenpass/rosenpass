use rosenpass::config::RosenpassConfig;
use std::path::PathBuf;

#[test]
fn example_config_rosenpass_new() {
    let (sk, pk) = ("./example.sk", "./example.pk");

    #[cfg(feature = "experiment_api")]
    {
        use rosenpass::config::{
            KeyFromDiskInner, NewFromInner, PublicPqKeySource, SecretPqKeySource,
        };

        assert_eq!(
            RosenpassConfig::new_empty(),
            RosenpassConfig::new_minimal(None, None)
        );
        assert_eq!(RosenpassConfig::new_empty(), RosenpassConfig::default());

        let mut v = RosenpassConfig::new_empty();
        v.our_keypair.secret_key_source =
            SecretPqKeySource::new(KeyFromDiskInner::File(PathBuf::from(pk)));
        v.our_keypair.public_key_source =
            PublicPqKeySource::new(KeyFromDiskInner::File(PathBuf::from(pk)));

        assert_eq!(
            RosenpassConfig::from_sk_pk(Some(PathBuf::from(sk)), Some(PathBuf::from(pk))),
            v
        );
    }

    #[cfg(not(feature = "experiment_api"))]
    assert_eq!(
        RosenpassConfig::from_sk_pk(sk, pk),
        RosenpassConfig::new_minimal(PathBuf::from(sk), PathBuf::from(pk))
    );
}
