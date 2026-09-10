use rosenpass::cfg;
use std::path::PathBuf;

#[test]
fn example_config_app_server_store() -> anyhow::Result<()> {
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    let tmpdir = tempfile::tempdir()?;

    let sk = tmpdir.path().join("example.sk");
    let pk = tmpdir.path().join("example.pk");
    let cfg = tmpdir.path().join("config.toml");

    let mut config = cfg::AppServer::from_sk_pk(&sk, &pk);

    // Can not commit config, path not known
    assert!(config.commit().is_err());

    // We can store it to an explicit path though
    config.store(&cfg)?;

    // Storing does not set commitment path
    assert!(config.commit().is_err());

    // We can reload the config now and the configurations
    // are equal if we adjust the commitment path
    let mut config2 = cfg::AppServer::load(&cfg)?;
    config.config_file_path = PathBuf::from(&cfg);
    assert_eq!(config, config2);

    // And this loaded config can now be committed
    config2.verbosity = cfg::Verbosity::Verbose;
    config2.commit()?;

    // And the changes actually made it to disk
    let config3 = cfg::AppServer::load(cfg)?;
    assert_eq!(config2, config3);
    assert_ne!(config, config3);

    Ok(())
}
