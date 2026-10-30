use super::{
    parse_from_cli::ParseWarning as CliParseWarning,
    parse_from_toml::ParseWarning as TomlParseWarning,
};
#[cfg(feature = "experiment_api")]
pub use crate::api::config::ApiConfig;
#[cfg(feature= "experiment_api")]
use crate::cli::BrokerInterface;
use crate::{
    config::Verbosity,
    protocol::{ProtocolVersion, osk_domain_separator::OskDomainSeparator},
};
use anyhow::bail;
use cidr::IpCidr;
pub use core::net::SocketAddr;
use debug_ignore::DebugIgnore;
use indexmap::IndexSet;
use std::{iter, path::PathBuf};

// submodules
pub mod keys;
pub use keys::*;

pub mod paths;
pub use paths::ResolvePathRelativeToConfig;

/// Configuration for Rosenpass
///
/// **NOTE:** all paths (e.g. to key files) are relative to the configuration's working directory
/// (the directory of the TOML file or the working directory of the shell calling the CLI). Use
/// [`ResolvePathRelativeToConfig`] to resolve these relative paths (see last lines of below
/// example).
///
/// ## Example
/// ```rust
#[doc = include_str!("../../../tests/config_rosenpass_load_from_file.rs")]
/// ```
///
/// ## TODO
/// - get rid of [`Serialize`] so that [`RosenpassConfig::store`] can use [`toml_edit`] introduced
///   in https://github.com/rosenpass/rosenpass/pull/1021
///
#[derive(Debug)]
pub struct RosenpassConfig {
    /// list of [`SocketAddr`] to listen on
    ///
    /// Examples:
    ///
    /// - `0.0.0.0:123` – Listen on any interface using IPv4, port 123
    /// - `[::1]:1234` – Listen on IPv6 localhost, port 1234
    /// - `[::]:4476` – Listen on any IPv4 or IPv6 interface, port 4476
    pub our_listen_addresses: Vec<SocketAddr>,

    /// log level, similar to [`log::LevelFilter`]
    pub verbosity: Verbosity,

    /// our static KEM keypair
    pub our_keypair: PqKeypairSource,

    /// all protocol versions supported by this Rosenpass instance
    ///
    /// This setting is currently true for all peers. A per-peer configuration might be introduced
    /// in the future, see https://github.com/rosenpass/rosenpass/issues/1181
    pub supported_protocol_versions: IndexSet<ProtocolVersion>,

    /// Location of the API listen sockets
    #[cfg(feature = "experiment_api")]
    pub api: ApiConfig,

    pub wireguard_devices: Vec<WgDeviceConfig>,
    pub peers: Vec<PeerConfig>,

    pub parsed_from: ConfigSource,
}
// ============================== [rosenpass] ==============================
#[derive(Debug)]
pub enum ConfigSource {
    TomlFile(ConfigSourceTomlFile),
    CommandLineArguments(ConfigSourceCli),

    /// the config has been procedurally generated from some calling Rust code
    ///
    /// This might appear for debugging purposed
    #[cfg_attr(
        feature = "experiment_api",
        doc = "or when reading configuration from the API"
    )]
    /// .
    GeneratedFromCode,
}

#[derive(Debug)]
pub struct ConfigSourceTomlFile {
    /// path to the TOML file which has been parsed
    pub file_path: PathBuf,

    /// the complete TOML document which has been parsed
    ///
    /// this will be omitted in the [`Debug`] output
    pub document: DebugIgnore<toml_edit::Document<String>>,

    /// all warnings caused by the parser
    pub warnings: Vec<TomlParseWarning>,

    /// config file version specified in `[rosenpass].config-file-version`
    pub file_version: TomlConfigFileVersion,
}
#[derive(Debug, Default)]
pub enum TomlConfigFileVersion {
    /// currently the only config file version
    ///
    /// This has been implicitly defined wucke13 in 2023 and extended by Ilka Schulz in 2026.
    #[default]
    Version1,
}
#[derive(Debug)]
pub struct ConfigSourceCli {
    /// full command line with "\0" as delimiter
    pub full_command_line: String,

    /// full command line with " " as delimiter
    pub full_command_line_human_readable: String,

    // TODO: maybe the entire PEST output?
    pub warnings: Vec<CliParseWarning>,
    // TODO: maybe some kind of grammar versioning?
}
// ============================== [[wiregard-devices]] ==============================
#[derive(Debug)]
pub struct WgDeviceConfig {
    /// name of the WireGuard device, e.g. `wg0`
    pub name: String,

    /// whether to actually use this config item
    pub enabled: bool,

    /// whether this device is created by someone else or by this application
    pub created_by: WgDeviceCreateOptions,
}
#[derive(Debug)]
pub enum WgDeviceCreateOptions {
    /// the WireGuard device needs to be created by this application
    Create(DeviceWireguardOptions),

    /// the WireGuard device has already been created by so. else
    ///
    /// If it later turns out that the device can not be found / has disappeared, then the
    /// application should throw an error.
    DoNotCreate,
}

/// flat version of [WgDeviceCreateOptions]
///
/// used as an intermediate result during parsing
#[derive(Debug, PartialEq)]
enum FlatWgDeviceCreateOptions {
    Create,
    DoNotCreate,
}

/// device's WireGuard options if the device is created
#[derive(Debug, Default)]
pub struct DeviceWireguardOptions {
    pub wg_listen_port: Option<u16>,
    pub wg_fwmark: Option<u16>,
}

// ============================== [[peers]] ==============================
#[derive(Debug)]
pub struct PeerConfig {
    /// cosmetic name of the peer
    pub name: String,

    /// whether the application should actually use this entry
    pub enabled: bool,

    /// public key of the peer (static KEM)
    pub their_public_key: PublicPqKeySource,

    /// endpoint of the peer's Rosenpass application
    pub endpoint: Option<String>,

    /// optional PSK used for the protocol context `ctx`, see whitepaper
    ///
    /// NOTE: This is only the PSK and _not_ the `uadc`/`uadi`/`uadr` mentioned in the whitepaper.
    /// Those are currently not implemented.
    pub preshared_key: Option<PresharedKeySource>,

    // TODO: implement `allowed-protocols`
    // https://github.com/rosenpass/rosenpass/issues/1181
    /// allows using a custom domain separator
    ///
    /// NOTE: This is the _legacy_ OSK domain separator defined per peer. In the future, the user
    /// should define their OSK domain separator per key usage (see [`PeerConfig::output_to_file`]
    /// and [`PeerConfig::wireguard`]).
    /// Tracking issue: https://github.com/rosenpass/rosenpass/issues/1182
    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,

    /// output key usage: write it to a file
    pub output_to_file: Option<OutputToFileConfig>,

    /// output key usage: supply WireGuard with it
    ///
    /// see whitepaper sec. 3.2 "Extension: WireGuard PSK"
    pub wireguard: Option<WireguardConfig>,
}
#[derive(Debug)]
pub enum PresharedKeySource {
    ReadFromFile(PathBuf),
    ReadFromDirectory(PathBuf),
}

impl PresharedKeySource {
    pub fn get_key_path(&self) -> PathBuf {
        match &self {
            Self::ReadFromFile(p) => p.clone(),
            Self::ReadFromDirectory(p) => p.join("psk"),
        }
    }
}

/// Configuration for [crate::protocol::osk_domain_separator::OskDomainSeparator]
///
/// Refer to its documentation for more information and examples of how to use this.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct RosenpassPeerOskDomainSeparator {
    /// If Rosenpass is used for purposes other then securing WireGuard,
    /// a custom domain separator and domain separator must be specified.
    ///
    /// Use `osk_organization` to indicate the organization who specifies the use case
    /// and `osk_label` for a specific purpose within that organization.
    ///
    /// ```toml
    /// [[peer]]
    /// public_key = "my_public_key"
    /// ...
    /// osk_organization = "myorg.com"
    /// osk_label = ["My Custom Messenger app"]
    /// ```
    pub osk_organization: Option<String>,
    // If Rosenpass is used for purposes other then securing WireGuard,
    /// a custom domain separator and domain separator must be specified.
    ///
    /// Use `osk_organization` to indicate the organization who specifies the use case
    /// and `osk_label` for a specific purpose within that organization.
    ///
    /// ```toml
    /// [[peer]]
    /// public_key = "my_public_key"
    /// ...
    /// osk_namespace = "myorg.com"
    /// osk_label = ["My Custom Messenger app"]
    /// ```
    ///
    /// TODO: flatten `Option<Vec<_>>` to `Vec<_>`
    pub osk_label: Option<Vec<String>>,
}

impl RosenpassPeerOskDomainSeparator {
    /// TODO: get rid of this match statement by simply using a proper type declaration and ensuring
    /// these rules during parsing
    pub fn org_and_label(&self) -> anyhow::Result<Option<(&String, &Vec<String>)>> {
        match (&self.osk_organization, &self.osk_label) {
            (None, None) => Ok(None),
            (Some(org), Some(label)) => Ok(Some((org, label))),
            (Some(_), None) => bail!(
                "Specified osk_organization but not osk_label in config file. You need to specify both, or none."
            ),
            (None, Some(_)) => bail!(
                "Specified osk_label but not osk_organization in config file. You need to specify both, or none."
            ),
        }
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let _org_and_label: Option<(_, _)> = self.org_and_label()?;
        Ok(())
    }
}

impl TryFrom<RosenpassPeerOskDomainSeparator> for OskDomainSeparator {
    type Error = anyhow::Error;

    fn try_from(val: RosenpassPeerOskDomainSeparator) -> anyhow::Result<Self> {
        match val.org_and_label()? {
            None => Ok(OskDomainSeparator::default()),
            Some((org, label)) => Ok(OskDomainSeparator::custom_utf8(org, label)),
        }
    }
}

#[derive(Debug)]
pub struct OutputToFileConfig {
    /// whether the application should actually use this entry
    pub enabled: bool,

    pub output_file_path: PathBuf,

    // TODO: use this custom OSK here
    // Tracking issue: https://github.com/rosenpass/rosenpass/issues/1182
    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,
}

#[derive(Debug)]
pub struct WireguardConfig {
    /// whether the application should actually use this entry
    pub enabled: bool,

    /// references a [WgDeviceConfig] by [`WgDeviceConfig::name`]
    pub device_name: String,

    pub our_wireguard_keypair: Option<OurWireguardKeypair>,

    pub their_wireguard_public_key: PublicWgKeySource,

    pub wireguard_options: PeerWireguardOptions,

    /// deprecated, will be dropped in https://github.com/rosenpass/rosenpass/issues/1184
    pub exchange_command: Option<Vec<String>>,

    // TODO: use this custom OSK here
    // Tracking issue: https://github.com/rosenpass/rosenpass/issues/1182
    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,
}

/// These are extra options supplied to the `wg` binary when configuring a peer
///
/// from wg's help:
/// ```
/// [endpoint <ip>:<port>]
/// [persistent-keepalive <interval seconds>]
/// [allowed-ips [+|-]<ip1>/<cidr1>[,[+|-]<ip2>/<cidr2>]...]
/// ```
#[derive(Debug, Default)]
pub struct PeerWireguardOptions {
    /// TODO: should this more strict (SocketAddr) or can it be a `<host>:<port>`?
    pub endpoint: Option<String>,
    pub persistent_keepalive: Option<usize>,

    /// allowed IP addresses for the WG peer
    ///
    /// This can be a list of addresses or networks.
    pub allowed_ips: Option<Vec<IpCidr>>,

    /// deprecated, will be dropped in https://github.com/rosenpass/rosenpass/issues/1183
    pub wg_extra_arguments: Vec<String>,
}

impl PeerWireguardOptions {
    pub fn to_cli_parameters(&self) -> Vec<String> {
        let mut items = vec![];
        if let Some(endpoint) = &self.endpoint {
            items.extend(vec!["endpoint".into(), endpoint.clone()]);
        }
        if let Some(persistent_keepalive) = &self.persistent_keepalive {
            items.extend(vec![
                "persistent-keepalive".into(),
                persistent_keepalive.to_string(),
            ])
        }
        if let Some(allowed_ips) = &self.allowed_ips {
            let allowed_ips = iter::once("allowed-ips".into())
                .chain(allowed_ips.iter().map(|ip| ip.to_string()))
                .collect::<Vec<String>>();
            items.extend(allowed_ips);
        }
        items.extend(self.wg_extra_arguments.clone());
        items
    }
}

#[derive(Debug)]
pub enum OurWireguardKeypair {
    PublicKeyOnly(PublicWgKeySource),
    EntireKeypair(WgKeypairSource),
}
impl OurWireguardKeypair {
    pub fn get_pubkey(&self) -> &PublicWgKeySource {
        match &self {
            Self::EntireKeypair(pair) => &pair.public_key_source,
            Self::PublicKeyOnly(pubkey) => pubkey
        }
    }
}