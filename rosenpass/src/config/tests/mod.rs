#![doc = include_str!("README.md")]
#![cfg(test)]

pub mod harness;

#[cfg(feature = "experiment_api")]
mod api;
mod conflicts;
mod example_files;
mod illegal_keys;
mod reject_secret_key;

use crate::config::tests::harness::{ExpectSilent, parse_string};

use super::*;

// TODO: test [`RosenpassConfig::validate`]

// TODO: test for missing keys – or does it even need testing?

// TODO: test for wrong types – or does it even need testing?

/// a minimal peer (only the mandatory key) parses with all optional fields empty
#[test]
fn minimal_peer_parses() -> Result<(), anyhow::Error> {
    let (config, _warnings) = parse_string(
        r#"
our-keypair = { secret-key-file = "../keys/alice-0.2-secret/pqsk", public-key-file = "../keys/alice-0.2-public/pqpk" }
listen = ["0.0.0.0:9999"]

[[peers]]
their-keypair = { public-key-file = "../keys/bob-0.2-public/pqpk" }
"#,
    )
    .expect_silent("parser returned errors");
    let peer = &config.peers[0];
    assert!(peer.enabled);
    assert_eq!(peer.endpoint, None);
    assert!(peer.preshared_key.is_none());
    assert!(peer.output_to_file.is_none());
    assert!(peer.wireguard.is_none());
    Ok(())
}
