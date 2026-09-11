use rosenpass::{cfg, cli::generate_and_save_keypair};
use std::fs;

#[test]
#[cfg_attr(miri, ignore)] // unsupported operation: can't call foreign function `mprotect` on OS `linux`
fn example_config_app_server_validate() -> anyhow::Result<()> {
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    let tmpdir = tempfile::tempdir()?;

    // Empty validates OK
    assert!(cfg::AppServer::empty().validate().is_ok());

    // Missing secret key does not pass usefulness
    assert!(cfg::AppServer::empty().check_usefullness().is_err());

    let sk = tmpdir.path().join("example.sk");
    let pk = tmpdir.path().join("example.pk");
    let config = cfg::AppServer::from_sk_pk(&sk, &pk);

    // Missing secret key does not validate
    assert!(config.validate().is_err());

    // But passes usefulness (the configuration is useful but invalid)
    assert!(config.check_usefullness().is_ok());

    // Providing empty key files does not help
    fs::write(&sk, b"")?;
    fs::write(&pk, b"")?;
    assert!(config.validate().is_err());

    // But after providing proper key files, the configuration validates
    generate_and_save_keypair(sk, pk)?;
    assert!(config.validate().is_ok());

    Ok(())
}
