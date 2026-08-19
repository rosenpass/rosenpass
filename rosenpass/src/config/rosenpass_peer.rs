use crate::config;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Configuration data for a single Rosenpass peer
#[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RosenpassPeer {
    /// path to the public key of the peer
    pub public_key: PathBuf,

    /// The hostname and port to connect to
    ///
    /// Can be a
    ///
    /// - hostname and port, e.g. `localhost:8876` or `rosenpass.eu:1427`
    /// - IPv4 address and port, e.g. `1.2.3.4:7764`
    /// - IPv6 address and port, e.g. `[fe80::24]:7890`
    pub endpoint: Option<String>,

    /// path to the pre-shared key shared with the peer
    ///
    /// NOTE: this item can be skipped in the config if you do not use a pre-shared key with the peer
    pub pre_shared_key: Option<PathBuf>,

    /// If this field is set to a path, the Rosenpass will write the exchanged symmetric keys
    /// to the given file and write a notification to standard out to let the calling application
    /// know that a new key was exchanged
    #[serde(default)]
    pub key_out: Option<PathBuf>,

    /// Information for supplying exchanged keys directly to WireGuard
    #[serde(flatten)]
    pub wg: Option<config::WireGuard>,

    #[serde(default)]
    /// The protocol version to use for the exchange
    pub protocol_version: config::ProtocolVersion,

    /// Allows using a custom domain separator
    #[serde(flatten)]
    pub osk_domain_separator: config::RosenpassPeerOskDomainSeparator,
}
