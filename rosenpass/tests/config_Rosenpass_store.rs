use std::path::PathBuf;

use rosenpass::config::{Rosenpass, Verbosity};

#[test]
fn example_config_rosenpass_store() -> anyhow::Result<()> {
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    let tmpdir = tempfile::tempdir()?;

    let sk = tmpdir.path().join("example.sk");
    let pk = tmpdir.path().join("example.pk");
    let cfg = tmpdir.path().join("config.toml");

    let mut c = Rosenpass::from_sk_pk(&sk, &pk);

    // Can not commit config, path not known
    assert!(c.commit().is_err());

    // We can store it to an explicit path though
    c.store(&cfg)?;

    // Storing does not set commitment path
    assert!(c.commit().is_err());

    // We can reload the config now and the configurations
    // are equal if we adjust the commitment path
    let mut c2 = Rosenpass::load(&cfg)?;
    c.config_file_path = PathBuf::from(&cfg);
    assert_eq!(c, c2);

    // And this loaded config can now be committed
    c2.verbosity = Verbosity::Verbose;
    c2.commit()?;

    // And the changes actually made it to disk
    let c3 = Rosenpass::load(cfg)?;
    assert_eq!(c2, c3);
    assert_ne!(c, c3);

    Ok(())
}
