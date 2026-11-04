use std::fs;

use rosenpass::{
    cli::run::generate_and_save_keypair,
    config::{
        RosenpassConfig,
        validate::{
            Error as ValidationError, Issue as ValidationIssue, ValidationRecipe,
            ValidationRecipeBuilder, Warning as ValidationWarning,
        },
    },
};

/// TODO: this test should check the exact validation result enum
#[test]
#[cfg_attr(miri, ignore)] // unsupported operation: can't call foreign function `mprotect` on OS `linux`
fn example_config_rosenpass_validate() -> anyhow::Result<()> {
    let tmpdir = tempfile::tempdir()?;
    // let validation_recipe = ValidationRecipe::all();

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
    let validation = cfg.validate(
        ValidationRecipeBuilder::new_empty()
            .check_whether_files_exist(true)
            .build(),
    );
    assert!(validation.is_err());
    assert!(validation.as_ref().err().unwrap().iter().any(|issue| {
        matches!(
            issue,
            ValidationIssue::Error(ValidationError::OurSecretKeyFileDoesNotExist(_))
        )
    }));

    // But passes usefulness (the configuration is useful but invalid)
    assert!(cfg.check_usefullness().is_ok());

    // Providing empty key files
    // - fixes the file existence check
    // - does not fix the file contents check
    fs::write(&sk, b"")?;
    fs::write(&pk, b"")?;
    let validation = cfg.validate(
        ValidationRecipeBuilder::new_empty()
            .check_whether_files_exist(true)
            .check_key_file_contents(true)
            .build(),
    );
    assert!(validation.is_err());
    assert!(!validation.as_ref().err().unwrap().iter().any(|issue| {
        matches!(
            issue,
            ValidationIssue::Error(ValidationError::OurSecretKeyFileDoesNotExist(_))
        )
    }));
    assert!(validation.as_ref().err().unwrap().iter().any(|issue| {
        matches!(
            issue,
            ValidationIssue::Error(ValidationError::OurSecretKeyFileHasInvalidContent(_, _))
        )
    }));

    // But after providing proper key files, the configuration validates
    generate_and_save_keypair(None, &sk, &pk, None, true)?;
    assert!(
        cfg.validate(
            ValidationRecipeBuilder::new_empty()
                .check_whether_files_exist(true)
                .check_key_file_contents(true)
                .build()
        )
        .is_ok()
    );

    Ok(())
}
