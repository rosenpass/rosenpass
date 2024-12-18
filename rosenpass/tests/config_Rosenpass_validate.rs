use std::fs;

use rosenpass::{cli::generate_and_save_keypair, config::Rosenpass};

#[test]
fn example_config_rosenpass_validate() -> anyhow::Result<()> {
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    let tmpdir = tempfile::tempdir()?;

    // Empty validates OK
    assert!(Rosenpass::empty().validate().is_ok());

    // Missing secret key does not pass usefulness
    assert!(Rosenpass::empty().check_usefullness().is_err());

    let sk = tmpdir.path().join("example.sk");
    let pk = tmpdir.path().join("example.pk");
    let cfg = Rosenpass::from_sk_pk(&sk, &pk);

    // Missing secret key does not validate
    assert!(cfg.validate().is_err());

    // But passes usefulness (the configuration is useful but invalid)
    assert!(cfg.check_usefullness().is_ok());

    // Providing empty key files does not help
    fs::write(&sk, b"")?;
    fs::write(&pk, b"")?;
    assert!(cfg.validate().is_err());

    // But after providing proper key files, the configuration validates
    generate_and_save_keypair(sk, pk)?;
    assert!(cfg.validate().is_ok());

    Ok(())
}
