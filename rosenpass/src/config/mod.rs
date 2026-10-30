//! contains the the type [`RosenpassConfig`] and parsing + validation code
//!
//! This module is split up into the follow submodules:
//! - [`types`]: contains the [`RosenpassConfig`] type and all associated types
//! - [`parse_from_cli`]: implements the function [`RosenpassConfig::parse_from_cli`]
//! - [`parse_from_toml`]: implements the function [`RosenpassConfig::parse_from_toml`]
//! - [`validate`]: implements the function [`RosenpassConfig::validate`]
//! - [`tests`]: contains unit tests

//! Configuration readable from a config file.
//!
//! Rosenpass supports reading its configuration from a TOML file. This module contains a struct
//! [`Rosenpass`] which holds such a configuration.
//!
//! ## TODO
//! - TODO: support `~` in <https://github.com/rosenpass/rosenpass/issues/237>
//! - TODO: provide tooling to create config file from shell <https://github.com/rosenpass/rosenpass/issues/247>
//!
pub mod parse_from_cli;
pub mod parse_from_toml;
pub mod tests;
pub mod types;
pub mod validate;

pub use types::*;

pub trait PrettyIssueOutput {
    fn pretty<'a>(&'a self, raw: &'a str) -> impl std::fmt::Display + 'a;
}

//
//
//
//
//
//
//
// old code below
//
//
//
//
//
//

use crate::app_server::AppServer;
use crate::cli::BrokerInterface;
use crate::protocol::ProtocolVersion;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6};
use std::path::{Path, PathBuf};

#[cfg(feature = "experiment_api")]
pub use crate::api::config::ApiConfig;

// TODO: remove old code (RosenpassConfig)
// /// Configuration for the Rosenpass key exchange
// ///
// /// i.e. configuration for the `rosenpass exchange` and `rosenpass exchange-config` commands
// #[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
// #[serde(deny_unknown_fields)]
// pub struct RosenpassConfig {
//     // TODO: Raise error if secret key or public key alone is set during deserialization
//     // SEE: https://github.com/serde-rs/serde/issues/2793
//     #[serde(flatten)]
//     pub our_keypair: Option<Keypair>,
//
//     /// Location of the API listen sockets
//     #[cfg(feature = "experiment_api")]
//     #[serde(default = "ApiConfig::new_empty")]
//     pub api: ApiConfig,
//
//     /// list of [`SocketAddr`] to listen on
//     ///
//     /// Examples:
//     ///
//     /// - `0.0.0.0:123` – Listen on any interface using IPv4, port 123
//     /// - `[::1]:1234` – Listen on IPv6 localhost, port 1234
//     /// - `[::]:4476` – Listen on any IPv4 or IPv6 interface, port 4476
//     pub our_listen_addresses: Vec<SocketAddr>,
//
//     /// log verbosity
//     ///
//     /// This is subject to change. See [`Verbosity`] for details.
//     #[serde(default)]
//     pub verbosity: Verbosity,
//
//     /// list of peers
//     ///
//     /// See the [`RosenpassPeer`] type for more information and examples.
//     pub peers: Vec<RosenpassPeer>,
//
//     /// path to the file which provided this configuration
//     ///
//     /// This item is of course not read from the TOML but is added by the algorithm that parses
//     /// the config file.
//     #[serde(skip)]
//     pub config_file_path: PathBuf,
// }

/// Level of verbosity for [crate::app_server::AppServer]
///
/// The value of the field [crate::app_server::AppServer::verbosity]. See the field documentation
/// for details.
///
/// - TODO: replace this type with [`log::LevelFilter`], also see <https://github.com/rosenpass/rosenpass/pull/246>
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone, Default)]
#[serde(deny_unknown_fields)]
pub enum Verbosity {
    #[default]
    Quiet,
    Verbose,
}

impl Verbosity {
    pub fn apply(&self) {
        let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)
        let level = match &self {
            Self::Verbose => log::LevelFilter::Info,
            Self::Quiet => log::LevelFilter::Warn,
        };
        log::debug!("setting log level to {:?}", level);
        log_builder.filter_level(level);
        log_builder.init();
    }
}

// TODO: remove dead code (RosenpassPeer)
// /// Configuration data for a single Rosenpass peer
// #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
// #[serde(deny_unknown_fields)]
// pub struct RosenpassPeer {
//     /// path to the public key of the peer
//     pub public_key: PathBuf,
//
//     /// The hostname and port to connect to
//     ///
//     /// Can be a
//     ///
//     /// - hostname and port, e.g. `localhost:8876` or `rosenpass.eu:1427`
//     /// - IPv4 address and port, e.g. `1.2.3.4:7764`
//     /// - IPv6 address and port, e.g. `[fe80::24]:7890`
//     pub endpoint: Option<String>,
//
//     /// path to the pre-shared key shared with the peer
//     ///
//     /// NOTE: this item can be skipped in the config if you do not use a pre-shared key with the peer
//     pub pre_shared_key: Option<PathBuf>,
//
//     /// If this field is set to a path, the Rosenpass will write the exchanged symmetric keys
//     /// to the given file and write a notification to standard out to let the calling application
//     /// know that a new key was exchanged
//     #[serde(default)]
//     pub key_out: Option<PathBuf>,
//
//     /// Information for supplying exchanged keys directly to WireGuard
//     #[serde(flatten, deserialize_with = "WireGuard::deserialize_optional")]
//     pub wg: Option<WireGuard>,
//
//     #[serde(default)]
//     /// The protocol version to use for the exchange
//     pub protocol_version: ProtocolVersion,
//
//     /// Allows using a custom domain separator
//     #[serde(flatten)]
//     pub osk_domain_separator: RosenpassPeerOskDomainSeparator,
// }

// TODO: remove dead code (Wireguard)
// /// Information for supplying exchanged keys directly to WireGuard
// #[derive(Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
// #[serde(deny_unknown_fields)]
// pub struct WireGuard {
//     /// Name of the WireGuard interface to supply with pre-shared keys generated by the Rosenpass
//     /// key exchange
//     pub device_name: String,
//
//     /// WireGuard public key of the peer to supply with pre-shared keys
//     pub peer: String,
//
//     /// our WireGuard public key – required since protocol version 3
//     #[serde(default)]
//     pub our_wg_pubkey: Option<String>,
//
//     /// Extra parameters passed to the `wg` command
//     #[serde(default)]
//     pub extra_params: Vec<String>,
// }
// impl WireGuard {
//     /// deserializes the entirety of the WireGuard protocol extension config
//     /// for one [`RosenpassPeer`]
//     ///
//     /// - If any of the WireGuard extension's config keys are present, this
//     /// returns `Some(WireGuard)`. All of the extension's config keys must
//     /// be absent to return `None`.
//     /// - The deserializer ensures that `device` and `peer` are set if any of
//     /// the other WireGuard extensions config keys are present.
//     ///
//     /// TODO: write tests for this deserialization
//     fn deserialize_optional<'de, D>(deserializer: D) -> Result<Option<Self>, D::Error>
//     where
//         D: serde::Deserializer<'de>,
//     {
//         use serde::de::Error as _;
//
//         // A flattened Option<WireGuard> silently discards missing required fields.
//         #[derive(Deserialize)]
//         #[serde(deny_unknown_fields)]
//         struct Fields {
//             device: Option<String>,
//             peer: Option<String>,
//             our_wg_pubkey: Option<String>,
//             extra_params: Option<Vec<String>>,
//         }
//
//         let fields = Fields::deserialize(deserializer)?;
//
//         match (
//             fields.device,
//             fields.peer,
//             fields.our_wg_pubkey,
//             fields.extra_params,
//         ) {
//             // if all fields are are None, the WireGuard extension is actually not used
//             (None, None, None, None) => Ok(None),
//
//             // if any field is Some(_), the WireGuard extension seems to be in use
//             (device, peer, our_wg_pubkey, extra_params) => Ok(Some(Self {
//                 // `device` and `peer` are required if the WireGuard extension is used
//                 device_name: device.ok_or_else(|| D::Error::missing_field("device"))?,
//                 peer: peer.ok_or_else(|| D::Error::missing_field("peer"))?,
//                 // `our_wg_pubkey` is optional because it is only required since protocol version 3.
//                 // `crate::config::Rosenpass::validate` will catch incosistencies depending on protocol version.
//                 our_wg_pubkey,
//                 // extra_params is optional and will just default to an empty list
//                 extra_params: extra_params.unwrap_or_default(),
//             })),
//         }
//     }
// }

impl Default for RosenpassConfig {
    /// Generate an empty configuration
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    ///
    /// TODO: get rid of [`Default`] here?
    fn default() -> Self {
        Self::new_empty()
    }
}

impl RosenpassConfig {
    /// Encode a configuration object as toml and write it to a file
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_store.rs")]
    #[doc = "```"]
    ///
    /// # TODO
    /// This does not take advantage of [`toml_edit`] newly introduced in
    /// https://github.com/rosenpass/rosenpass/pull/1021
    pub fn store<P: AsRef<Path>>(&self, p: P) -> anyhow::Result<()> {
        todo!("this is currently not implemented as it is not part of the app logic anyways");
        #[cfg(none)]
        {
            let serialized_config =
                toml::to_string_pretty(&self).expect("unable to serialize the default config");
            fs::write(p, serialized_config)?;
            Ok(())
        }
    }

    /// Commit the configuration to where it came from, overwriting the original file
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_store.rs")]
    #[doc = "```"]
    pub fn commit(&self) -> anyhow::Result<()> {
        todo!("this is currently not implemented as it is not part of the app logic anyways");
        #[cfg(none)]
        {
            let mut f = fopen_w(&self.config_file_path, Visibility::Public)?;
            f.write_all(toml::to_string_pretty(&self)?.as_bytes())?;

            self.store(&self.config_file_path)
        }
    }

    /// Apply the configuration in this object to the given [crate::app_server::AppServer]
    ///
    /// TODO: this is only the API configuration and no the rest of the config
    pub fn apply_to_app_server(&self, _srv: &mut AppServer) -> anyhow::Result<()> {
        #[cfg(feature = "experiment_api")]
        self.api.apply_to_app_server(_srv)?;
        Ok(())
    }

    /// Produce an empty confuguration
    ///
    /// ## Panics
    /// This function will only run with the experimental feature `experiment_api` enabled.
    /// Otherwise, it will panic as it lacks the minimal settings.
    /// Use [`RosenpassConfig::new_minimal`] if you want a minimal functioning configuration.
    ///
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    pub fn new_empty() -> Self {
        Self {
            our_listen_addresses: vec![],
            verbosity: Verbosity::Quiet,
            our_keypair: PqKeypairSource {
                secret_key_source: KeyFromDisk::new({
                    #[cfg(feature = "experiment_api")]
                    {
                        KeyFromDiskInner::None
                    }
                    #[cfg(not(feature = "experiment_api"))]
                    {
                        panic!(
                            "RosenpassConfig::new_empty() requires feature `experiment_api`. This is a bug."
                        )
                    }
                }),
                public_key_source: KeyFromDisk::new({
                    #[cfg(feature = "experiment_api")]
                    {
                        KeyFromDiskInner::None
                    }
                    #[cfg(not(feature = "experiment_api"))]
                    {
                        panic!(
                            "RosenpassConfig::new_empty() requires feature `experiment_api`. This is a bug."
                        )
                    }
                }),
            },
            supported_protocol_versions: ProtocolVersion::all_supported_by_default(),
            #[cfg(feature = "experiment_api")]
            api: ApiConfig::new_empty(),
            wireguard_devices: vec![],
            peers: vec![],
            parsed_from: ConfigSource::GeneratedFromCode,
        }
    }

    /// produce a minimal configuration from a PQ keypair specifed via their file paths
    ///
    /// This is a shorthand [`Self::new_minimal`].
    ///
    /// **NOTE**: the paths must refer to the keys' **file** paths, not their directories
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    pub fn from_sk_pk<Sk: AsRef<Path>, Pk: AsRef<Path>>(sk: Sk, pk: Pk) -> Self {
        Self::new_minimal(sk.as_ref().to_path_buf(), pk.as_ref().to_path_buf())
    }

    /// produce a minimal configuration with our PQ keypair supplied as a parameter
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_new.rs")]
    #[doc = "```"]
    pub fn new_minimal(our_secret_key_file: PathBuf, our_public_key_file: PathBuf) -> Self {
        Self {
            our_listen_addresses: vec![],
            verbosity: Verbosity::Quiet,
            our_keypair: PqKeypairSource {
                secret_key_source: SecretPqKeySource::new(KeyFromDiskInner::File(
                    our_secret_key_file,
                )),
                public_key_source: PublicPqKeySource::new(KeyFromDiskInner::File(
                    our_public_key_file,
                )),
            },
            supported_protocol_versions: ProtocolVersion::all_supported_by_default(),
            #[cfg(feature = "experiment_api")]
            api: ApiConfig::new_empty(),
            wireguard_devices: vec![],
            peers: vec![],
            parsed_from: ConfigSource::GeneratedFromCode,
        }
    }

    /// Add IPv4 __and__ IPv6 IF_ANY address to the listen interfaces
    ///
    /// I.e. listen on any interface.
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/config_Rosenpass_add_if_any.rs")]
    #[doc = "```"]
    pub fn add_if_any(&mut self, port: u16) {
        let ipv4_any = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), port));
        let ipv6_any = SocketAddr::V6(SocketAddrV6::new(
            Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0),
            port,
            0,
            0,
        ));
        self.our_listen_addresses.push(ipv4_any);
        self.our_listen_addresses.push(ipv6_any);
    }
}

/// Example configuration generated by the command `rosenpass gen-config <TOML-FILE>`.
///
/// TODO: new example config
pub static EXAMPLE_CONFIG: &str = r###"public_key = "/path/to/rp-public-key"
secret_key = "/path/to/rp-secret-key"
listen = [] # socket address to listen on (e.g. "[::]:10002")
verbosity = "Verbose" # options: "Quiet", "Verbose"

[[peers]]
# Commented out fields are optional
public_key = "/path/to/rp-peer-public-key"
endpoint = "127.0.0.1:9998"
# pre_shared_key = "/path/to/preshared-key"

# Choose to store the key in a file via `key_out` or pass it to WireGuard.
# You can also choose to do both.

# ========== outfile option ==========
# You can save the key from the handshake to a file.
key_out = "/path/to/rp-key-out.txt" # path to store the key

# ========== options for the WireGuard extension ==========
# Using the WireGuard extension is optional.
# See the whitepaper section 3.2 for more information.
# https://rosenpass.eu/docs/whitepaper

# device = "wg0" # WireGuard interface
# peer = "RULdRAtUw7SFfVfGD..." # WireGuard public key
# our_wg_pubkey = "LDn3YQZ3+4V..." # our WireGuard public key, required since protocol version 3
# extra_params = [] # passed to WireGuard `wg set`
"###;
