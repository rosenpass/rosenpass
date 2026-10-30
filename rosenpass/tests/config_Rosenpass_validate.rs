use std::fs;

use rosenpass::{
    cli::run::generate_and_save_keypair,
    config::{RosenpassConfig, validate::ValidationRecipe},
};

#[test]
#[cfg_attr(miri, ignore)] // unsupported operation: can't call foreign function `mprotect` on OS `linux`
fn example_config_rosenpass_validate() -> anyhow::Result<()> {
    let tmpdir = tempfile::tempdir()?;
    let validation_recipe = ValidationRecipe::all();

    // empty configurations are possible with the experimental API feature enabled
    #[cfg(feature = "experiment_api")]
    let _ = RosenpassConfig::new_empty();

    // missing secret key does not pass usefulness with experimental API feature enabled
    #[cfg(feature = "experiment_api")]
    assert!(RosenpassConfig::new_empty().check_usefullness().is_err());

    let sk = tmpdir.path().join("example.sk");
    let pk = tmpdir.path().join("example.pk");
    #[cfg(feature = "experiment_api")]
    let cfg = RosenpassConfig::from_sk_pk(Some(&sk), Some(&pk));
    #[cfg(not(feature = "experiment_api"))]
    let cfg = RosenpassConfig::from_sk_pk(&sk, &pk);

    // missing secret key (file does not exist) does not validate
    assert!(cfg.validate(validation_recipe).is_err());

    // But passes usefulness (the configuration is useful but invalid)
    assert!(cfg.check_usefullness().is_ok());

    // Providing empty key files does not help
    fs::write(&sk, b"")?;
    fs::write(&pk, b"")?;
    assert!(cfg.validate(validation_recipe).is_err());

    // But after providing proper key files, the configuration validates
    generate_and_save_keypair(&sk, &pk, true)?;
    assert!(cfg.validate(validation_recipe).is_ok());

    Ok(())
}
