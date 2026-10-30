//! TODO: doc
//!
//! TODO: test [`RosenpassConfig::parse_from_cli`]
//!

pub mod harness;
pub use harness::*;

#[cfg(feature = "experiment_api")]
use crate::config::ApiConfig;
use crate::{
    config::{
        ConfigSource, PresharedKeySource, PublicKeySource,
        parse_from_toml::util::default_peer_name, tests::test_toml::harness::ExpectSilent,
    },
    config::{RosenpassPeerOskDomainSeparator, Verbosity},
    protocol::ProtocolVersion,
};
use cidr::IpCidr;
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

/// parse command line from rosenpass 0.2.3
#[test]
fn parse_full_rosenpass_0_2() {
    let line = format!(
        r#"
rosenpass exchange 
    public-key {ALICE_PUBFILE} secret-key {ALICE_SECFILE} listen {ALICE_LISTEN_0} listen {ALICE_LISTEN_1} verbose
    peer public-key {BOB_PUBFILE} endpoint {BOB_ENDPOINT} preshared-key {BOB_PSK}
        outfile {BOB_OUTFILE}
        wireguard {BOB_WG_DEV} {BOB_WG_PUB} {BOB_WG_EXTRA_ARGS}
    peer public-key {CHARLIE_PUBFILE}
    --config-file {BOB_CONF}
"#
    );
    let (result, warnings) = parse_str(&line).expect_silent("parsing failed");

    assert_eq!(
        result.our_keypair.public_key_source.get_key_path(),
        PathBuf::from(ALICE_PUBFILE)
    );
    assert_eq!(
        result.our_keypair.secret_key_source.get_key_path(),
        PathBuf::from(ALICE_SECFILE)
    );
    assert_eq!(
        result.our_listen_addresses,
        [
            SocketAddr::from_str(ALICE_LISTEN_0).unwrap(),
            SocketAddr::from_str(ALICE_LISTEN_1).unwrap(),
        ]
    );
    assert_eq!(result.verbosity, Verbosity::Verbose);
    assert_eq!(
        result.supported_protocol_versions,
        ProtocolVersion::all_supported_by_default()
    );

    #[cfg(feature = "experiment_api")]
    assert_eq!(result.api, ApiConfig::new_empty());

    assert_eq!(result.peers.len(), 2);

    // peer "bob"
    {
        let bob = &result.peers[0];
        assert_eq!(bob.name, default_peer_name(0));
        assert!(bob.enabled);
        assert_eq!(
            bob.their_public_key.get_key_path(),
            PathBuf::from(BOB_PUBFILE)
        );
        assert_eq!(bob.endpoint.as_deref(), Some(BOB_ENDPOINT));
        let Some(PresharedKeySource::ReadFromFile(psk_path)) = &bob.preshared_key else {
            panic!(
                "peer's preshared key should be read from the file, got {:?}",
                bob.preshared_key
            )
        };
        assert_eq!(psk_path, &PathBuf::from(BOB_PSK));
        assert_eq!(
            bob.osk_domain_separator,
            RosenpassPeerOskDomainSeparator {
                osk_organization: None,
                osk_label: None,
            }
        );

        // key output to file
        let Some(outfile) = &bob.output_to_file else {
            panic!("bob's key should be written to the file {BOB_OUTFILE}")
        };
        assert!(outfile.enabled);
        assert_eq!(outfile.output_file_path, PathBuf::from(BOB_OUTFILE));
        assert_eq!(
            outfile.osk_domain_separator,
            RosenpassPeerOskDomainSeparator {
                osk_organization: None,
                osk_label: None,
            }
        );

        // wireguard extension
        let Some(wireguard) = &bob.wireguard else {
            panic!("bob's key should be supplied to wireguard")
        };
        assert!(wireguard.enabled);
        assert_eq!(wireguard.device_name, BOB_WG_DEV);
        assert!(wireguard.our_wireguard_keypair.is_none());
        assert!(
            wireguard
                .their_wireguard_public_key
                .get_key_path()
                .is_none()
        );
        assert_eq!(
            wireguard
                .their_wireguard_public_key
                .get_inline_key()
                .as_deref(),
            Some(BOB_WG_PUB.trim())
        );
        let options = &wireguard.wireguard_options;
        assert_eq!(options.endpoint.as_deref(), Some("7.6.5.4:6543"));
        assert_eq!(options.persistent_keepalive, Some(123));
        let expected_allowed_ips = ["9.8.7.6", "1234::", "8.7.6.0/24", "2345::/16"]
            .into_iter()
            .map(|s| IpCidr::from_str(s).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(options.allowed_ips, Some(expected_allowed_ips));
        assert!(options.wg_extra_arguments.is_empty());
        assert!(wireguard.exchange_command.is_none());
        assert_eq!(wireguard.osk_domain_separator, Default::default());
    }

    // peer "charlie"
    {
        let charlie = &result.peers[1];
        assert_eq!(charlie.name, default_peer_name(1));
        assert!(charlie.enabled);
        assert_eq!(
            charlie.their_public_key.get_key_path(),
            PathBuf::from(CHARLIE_PUBFILE)
        );
        assert!(charlie.endpoint.is_none());
        assert!(charlie.preshared_key.is_none());
        assert_eq!(
            charlie.osk_domain_separator,
            RosenpassPeerOskDomainSeparator {
                osk_organization: None,
                osk_label: None,
            }
        );
        assert!(charlie.output_to_file.is_none());
        assert!(charlie.wireguard.is_none());

        assert!(result.wireguard_devices.is_empty());

        // check the record of where this config was parsed from
        let ConfigSource::CommandLineArguments(_) = &result.parsed_from else {
            panic!(
                "expected the config to be parsed from the command line, got {:?}",
                result.parsed_from
            )
        };
    }

    // check the record of where this config was parsed from
    let ConfigSource::CommandLineArguments(source) = &result.parsed_from else {
        panic!(
            "config not parsed from command line, got {:?}",
            result.parsed_from
        )
    };
    assert!(source.warnings.is_empty());

    assert!(warnings.is_empty(), "unexpected warnings: {warnings:?}");
}

// /// TODO: parse command line from rp 0.2.3
// #[test]
// fn parse_full_rp_0_2() {
//     // let line = todo!();
//     // let result = parse_str(&line).expect_silent("parsing failed").0;
//     todo!("assertions")
// }

// TODO: refuse other subcommands than exchange

// TODO: parse legacy
// rosenpass exchange <OWN_CONFIG> [PEERS]...
//     OWN_CONFIG: public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose]
//     PEERS...: peer public-key <PATH> [endpoint <HOST/IP>:<PORT>] [preshared-key <PATH>]
//        [outfile <PATH>]
//        [wireguard <WIREGUARD_DEV> <WIREGUARD_PEER> [WIREGUARD_EXTRA_ARGS]...]
//        [-c, --config-file <CONFIG_FILE>] TODO: how where is this located?

// TODO: parse rp
// rp exchange <PRIVATE_KEYS_DIR> [dev <device>] [listen <ip>:<port>] [PEERS]...
//     PEER: peer <PUBLIC_KEYS_DIR> [endpoint <ip>:<port>] [persistent-keepalive <interval>]
//         [allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...]

// TODO: parse `main` branch
// rosenpass exchange [-c, --config-file <CONFIG_OUTPUT_FILE>] <OWN_CONFIG> [PEERS]...
//     OWN_CONFIG: public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose]
//     PEER: peer public-key <PATH> [endpoint <HOST/IP>:<PORT>] [preshared-key <PATH>]
//         [outfile <PATH>]
//         [wireguard <WIREGUARD_DEV> <WIREGUARD_PEER> [WIREGUARD_EXTRA_ARGS]...]

// TODO: parse modern
// rosenpass config create
// TODO: and many more
