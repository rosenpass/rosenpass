//! test the example files in `data/configs/*.toml`
use super::super::*;
use super::harness::{ExpectSilent, parse, prepare_config};
use crate::config::Verbosity;
use crate::protocol::ProtocolVersion;
use std::path::{Path, PathBuf};

#[test]
fn read_full_config_with_version_0_2_keys() -> Result<(), anyhow::Error> {
    #[rustfmt::skip]
    let (config, file_path) = prepare_config(
        Path::new("full-raw.toml"),
        vec![
            ("rosenpass.our-keypair.secret-key-file", "../keys/alice-0.2-secret/pqsk".into()),
            ("rosenpass.our-keypair.public-key-file", "../keys/alice-0.2-public/pqpk".into()),
            ("peers.0.their-keypair.public-key-file", "../keys/bob-0.2-public/pqpk".into()),
            ("peers.0.preshared-key.file", "../keys/alice-bob.psk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.secret-key-file", "../keys/alice-0.2-secret/wgsk".into()),
            ("peers.0.wireguard.our-wireguard-keypair.public-key-file", "../keys/alice-0.2-public/wgpk".into()),
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

    // [rosenpass] table
    assert_eq!(
        config.our_listen_addresses.as_slice(),
        ["0.0.0.0:9999".parse().unwrap()]
    );
    assert_eq!(config.verbosity, Verbosity::Verbose);
    assert!(
        config
            .supported_protocol_versions
            .contains(&ProtocolVersion::V02)
    );
    assert!(
        config
            .supported_protocol_versions
            .contains(&ProtocolVersion::V03)
    );
    assert_eq!(config.supported_protocol_versions.len(), 2);
    assert_eq!(
        config.our_keypair.secret_key_source.get_secret_key_path(),
        PathBuf::from("../keys/alice-0.2-secret/pqsk")
    );
    assert_eq!(
        config.our_keypair.public_key_source.get_key_path(),
        PathBuf::from("../keys/alice-0.2-public/pqpk")
    );
    let ConfigSource::TomlFile(source) = &config.parsed_from else {
        panic!("not parsed from TOML file");
    };
    assert!(matches!(
        source.file_version,
        TomlConfigFileVersion::Version1
    ));

    // api
    #[cfg(feature = "experiment_api")]
    {
        assert!(config.api.listen_path.is_empty());
        assert!(config.api.listen_fd.is_empty());
        assert!(config.api.stream_fd.is_empty());
    }

    // [[wireguard-devices]]
    assert_eq!(config.wireguard_devices.len(), 1);
    let device = &config.wireguard_devices[0];
    assert_eq!(device.name, "wg0");
    assert!(device.enabled);
    match &device.created_by {
        WgDeviceCreateOptions::Create(DeviceWireguardOptions {
            wg_listen_port,
            wg_fwmark,
        }) => {
            assert_eq!(*wg_listen_port, Some(1234));
            assert_eq!(*wg_fwmark, Some(0x1234));
        }
        other => panic!("unexpected value for wireguard-device.create: {other:?}"),
    }

    // [[peers]]
    assert_eq!(config.peers.len(), 1);
    let peer = &config.peers[0];
    assert_eq!(peer.name, "bob");
    assert!(peer.enabled);
    assert_eq!(
        peer.their_public_key.get_key_path(),
        PathBuf::from("../keys/bob-0.2-public/pqpk")
    );
    assert_eq!(peer.endpoint.as_deref(), Some("1.2.3.4:9999"));
    match &peer.preshared_key {
        Some(PresharedKeySource::ReadFromFile(path)) => {
            assert_eq!(path, &PathBuf::from("../keys/alice-bob.psk"))
        }
        other => panic!("unexpected PSK source: {other:?}"),
    }
    assert_eq!(
        peer.osk_domain_separator.osk_organization.as_deref(),
        Some("my.org")
    );
    assert_eq!(
        peer.osk_domain_separator.osk_label,
        Some(vec!["My App".to_string()])
    );

    let key_out = peer.output_to_file.as_ref().expect("key-out missing");
    assert!(key_out.enabled);
    assert_eq!(
        key_out.output_file_path,
        PathBuf::from("path/to/optional-output-file.txt")
    );
    assert_eq!(
        key_out.osk_domain_separator.osk_organization.as_deref(),
        Some("my.org")
    );
    assert_eq!(
        key_out.osk_domain_separator.osk_label,
        Some(vec!["My App".to_string()])
    );

    let wireguard = peer.wireguard.as_ref().expect("wireguard missing");
    assert!(wireguard.enabled);
    assert_eq!(wireguard.device_name, "wg0");
    match &wireguard.our_wireguard_keypair {
        Some(OurWireguardKeypair::EntireKeypair(keypair)) => {
            assert_eq!(
                keypair.secret_key_source.get_secret_key_path(),
                PathBuf::from("../keys/alice-0.2-secret/wgsk")
            );
            assert_eq!(
                keypair.public_key_source.get_key_path(),
                Some(PathBuf::from("../keys/alice-0.2-public/wgpk"))
            );
        }
        other => panic!("unexpected (our) wireguard keypair: {other:?}"),
    }
    assert_eq!(
        wireguard.their_wireguard_public_key.get_key_path(),
        Some(PathBuf::from("path/to/their.pk"))
    );
    assert_eq!(
        wireguard.wireguard_options.endpoint.as_deref(),
        Some("1.2.3.4:1234")
    );
    assert_eq!(wireguard.wireguard_options.persistent_keepalive, Some(25));
    assert_eq!(
        wireguard.wireguard_options.allowed_ips,
        Some(vec!["1.2.3.0/24".parse().unwrap()])
    );
    assert_eq!(
        wireguard.wireguard_options.wg_extra_arguments,
        vec!["TODO".to_string()]
    );
    assert_eq!(
        wireguard.exchange_command,
        Some(vec![
            "wg".to_string(),
            "set".to_string(),
            "wg0".to_string(),
            "peer".to_string(),
            "<PEER_ID>".to_string(),
            "preshared-key".to_string(),
            "/dev/stdin".to_string(),
        ])
    );
    assert_eq!(
        wireguard.osk_domain_separator.osk_organization.as_deref(),
        Some("my.org")
    );

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

    // empty listen addresses list
    assert_eq!(parse_warnings.len(), 1);
    assert!(
        parse_warnings[0]
            .message
            .contains("listen addresses list is empty")
    );

    // legacy keys at document root
    assert!(config.our_listen_addresses.is_empty());
    assert_eq!(config.verbosity, Verbosity::Quiet);
    assert_eq!(
        config.our_keypair.secret_key_source.get_secret_key_path(),
        PathBuf::from("../keys/alice-0.2-public/pqsk")
    );

    // [[peers]]
    assert_eq!(config.peers.len(), 1);
    let peer = &config.peers[0];

    let key_out = peer.output_to_file.as_ref().expect("key_out missing");
    assert!(key_out.enabled);
    assert_eq!(key_out.output_file_path, PathBuf::from("rp-key-out"));

    // legacy wireguard definition: device name extracted from the exchange command
    let wireguard = peer.wireguard.as_ref().expect("wireguard missing");
    assert!(wireguard.enabled);
    assert_eq!(wireguard.device_name, "wg0");
    assert!(wireguard.our_wireguard_keypair.is_none());
    assert_eq!(
        wireguard
            .their_wireguard_public_key
            .get_inline_key()
            .expect("wireguard public key missing"),
        "<PEER_ID>"
    );
    assert!(wireguard.exchange_command.is_some());

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

    // the legacy config has an empty listen addresses list
    assert_eq!(parse_warnings.len(), 1);
    assert!(
        parse_warnings[0]
            .message
            .contains("listen addresses list is empty")
    );

    // [[peers]]
    assert_eq!(config.peers.len(), 1);
    let peer = &config.peers[0];
    assert_eq!(peer.name, "peer no. 0");
    match &peer.preshared_key {
        Some(PresharedKeySource::ReadFromFile(path)) => {
            assert_eq!(path, &PathBuf::from("file/to/psk"))
        }
        other => panic!("expected PSK read from file, got: {other:?}"),
    }

    // legacy wireguard definition
    let wireguard = peer.wireguard.as_ref().expect("wireguard missing");
    assert_eq!(wireguard.device_name, "wg0");
    // `our_wg_pubkey` is a base64-encoded inline public key in the legacy format
    match &wireguard.our_wireguard_keypair {
        Some(OurWireguardKeypair::PublicKeyOnly(key)) => {
            assert_eq!(
                key.get_inline_key().as_deref(),
                Some("<base64 of our own `wg pubkey`>")
            );
        }
        other => panic!("expected our wireguard public key only, got: {other:?}"),
    }
    // `peer` is a base64-encoded wireguard pubkey
    assert_eq!(
        wireguard
            .their_wireguard_public_key
            .get_inline_key()
            .expect("their wireguard public key missing"),
        "<base64 of the peer's `wg pubkey`>"
    );
    assert!(wireguard.wireguard_options.wg_extra_arguments.is_empty());

    Ok(())
}
