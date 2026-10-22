#![doc = include_str!("README.md")]
#![cfg(test)]

pub mod harness;

use std::path::Path;

use crate::config::validate::ValidationRecipe;

use super::*;
use harness::{assert_validation_succeeded, parse, prepare_config_file, validate};
use serial_test::serial;

// #[ignore] // TODO: remove ignore before merging into main
// #[test]
// fn read_full_config_with_version_0_2_keys() {
//     let (config, working_dir) = read_toml(Path::new("full-with-v0.2-keys.toml")).unwrap();
//     let (config, parse_warnings) = parse(config, &working_dir).expect("parser returned errors");
//     assert!(parse_warnings.is_empty(), "parser returned warnings");
//     assert_validation_succeeded(validate(&config, ValidationRecipe::all()));
//     // let warnings = validate(&config, ValidationRecipe::all()).expect("validation returned errors");
//     // assert!(warnings.is_empty(), "validation returned warnings");
// }

#[test]
#[serial] // run in serial so that no race-conditions around "tmp.toml" file can be avoided
fn read_full_config_with_version_0_2_keys() -> Result<(), anyhow::Error> {
    #[rustfmt::skip]
    let (config, working_dir) = prepare_config_file(
        Path::new("full-raw.toml"),
        Path::new("tmp.toml"),
        vec![
            ("rosenpass.our-keypair.secret-key-file", "../keys/alice-0.2-secret/pqsk".into()),
            ("rosenpass.our-keypair.public-key-file", "../keys/alice-0.2-public/pqpk".into()),
            ("peers.0.their-keypair.public-key-file", "../keys/bob-0.2-public/pqpk".into()),
            ("peers.0.preshared-key.file", "../alice-bob.psk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.secret-key-file", "../keys/alice-wg-secret/wqsk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.public-key-file", "../keys/alice-wg-public/wgpk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.public-key", "TODO".into()),
        ],
        vec![
            ("peers.0.their-keypair.public-key-directory"),
            ("peers.0.preshared-key.directory")
        ],
        vec![],
    )?;
    let (config, parse_warnings) = parse(config, &working_dir).expect("parser returned errors");
    assert_validation_succeeded(validate(&config, ValidationRecipe::all()));
    assert!(parse_warnings.is_empty(), "parser returned warnings");

    Ok(())
}

#[test]
#[serial]
fn read_old_config_with_version_0_2_keys() -> Result<(), anyhow::Error> {
    let (config, working_dir) = prepare_config_file(
        Path::new("rosenpass-0.2.3-generated-raw.toml"),
        Path::new("tmp.toml"),
        vec![
            ("public_key", "../keys/alice-0.2-public/pqpk".into()),
            ("secret_key", "../keys/alice-0.2-public/pqsk".into()),
            ("peers.0.public_key", "../keys/bob-0.2-public/pqpk".into()),
        ],
        vec![],
        vec![],
    )?;
    let (config, _parse_warnings) = parse(config, &working_dir).expect("parser returned errors");
    assert_validation_succeeded(validate(&config, ValidationRecipe::all()));

    Ok(())
}

// TODO: test that additional keys are rejected

// TODO: test that peer secret key is rejected

// TODO: `rosenpass-0.2.3-full-raw.toml`