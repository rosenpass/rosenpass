#![doc = include_str!("README.md")]
#![cfg(test)]

pub mod harness;

#[cfg(feature = "experiment_api")]
mod api;
use std::path::Path;

use crate::config::{tests::harness::ExpectSilent, validate::ValidationRecipe};

use super::*;
use harness::{assert_validation_succeeded, parse, prepare_config, validate};
use serial_test::serial;

#[test]
#[serial] // run in serial so that no race-conditions around "tmp.toml" file can be avoided
fn read_full_config_with_version_0_2_keys() -> Result<(), anyhow::Error> {
    #[rustfmt::skip]
    let (config, file_path) = prepare_config(
        Path::new("full-raw.toml"),
        vec![
            ("rosenpass.our-keypair.secret-key-file", "../keys/alice-0.2-secret/pqsk".into()),
            ("rosenpass.our-keypair.public-key-file", "../keys/alice-0.2-public/pqpk".into()),
            ("peers.0.their-keypair.public-key-file", "../keys/bob-0.2-public/pqpk".into()),
            ("peers.0.preshared-key.file", "../alice-bob.psk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.secret-key-file", "../keys/alice-wg-secret/wqsk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.public-key-file", "../keys/alice-wg-public/wgpk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.public-key", "TODO: also test this".into()),
        ],
        vec![
            "peers.0.their-keypair.public-key-directory",
            "peers.0.wireguard.our-wireguard-keypair.public-key",
            "peers.0.wireguard.their-wireguard-keypair.public-key-directory",
            "peers.0.wireguard.their-wireguard-keypair.public-key",
            "peers.0.preshared-key.directory",
        ],
        vec![],
    )?;
    let (config, parse_warnings) =
        parse(config, &file_path).expect_silent("parser returned errors");
    // without the `experiment_api` feature, the `[rosenpass.api]` table produces a warning
    #[cfg(feature = "experiment_api")]
    assert!(parse_warnings.is_empty(), "parser returned warnings");
    #[cfg(not(feature = "experiment_api"))]
    assert!(
        parse_warnings
            .iter()
            .all(|w| w.message.contains("experiment_api")),
        "unexpected parser warnings: {parse_warnings:?}"
    );

    // TODO: write

    Ok(())
}

#[test]
fn read_v0_2_generated_config_with_version_0_2_keys() -> Result<(), anyhow::Error> {
    let (config, file_path) = prepare_config(
        Path::new("rosenpass-0.2.3-generated-raw.toml"),
        vec![
            ("public_key", "../keys/alice-0.2-public/pqpk".into()),
            ("secret_key", "../keys/alice-0.2-public/pqsk".into()),
            ("peers.0.public_key", "../keys/bob-0.2-public/pqpk".into()),
        ],
        vec![],
        vec![],
    )?;
    let (config, parse_warnings) =
        parse(config, &file_path).expect_silent("parser returned errors");

    // TODO: write
    
    Ok(())
}

#[test]
fn read_v0_2_full_config_with_version_0_2_keys() -> Result<(), anyhow::Error> {
    let (config, file_path) = prepare_config(
        Path::new("rosenpass-0.2.3-full-raw.toml"),
        vec![
            ("public_key", "../keys/alice-0.2-public/pqpk".into()),
            ("secret_key", "../keys/alice-0.2-public/pqsk".into()),
            ("peers.0.public_key", "../keys/bob-0.2-public/pqpk".into()),
        ],
        vec![],
        vec![],
    )?;
    let (config, parse_warnings) =
        parse(config, &file_path).expect_silent("parser returned errors");

    // TODO: write
    

    Ok(())
}
// TODO: test that additional keys are rejected

// TODO: test that peer secret key is rejected

// TODO: test that all paths have been resolved
