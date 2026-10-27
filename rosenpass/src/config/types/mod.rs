use super::parse_from_toml::ParseWarning as TomlParseWarning;
#[cfg(feature = "experiment_api")]
pub use crate::api::config::ApiConfig;
use crate::{
    oldconfig::{RosenpassPeerOskDomainSeparator, Verbosity},
    protocol::ProtocolVersion,
};
use cidr::IpCidr;
pub use core::net::SocketAddr;
use debug_ignore::DebugIgnore;
use std::{collections::HashSet, path::PathBuf};

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
/// use crate::config::ResolvePathRelativeToConfig;
/// use anyhow::anyhow;
///
/// // read config file from disk
/// let file_path = PathBuf::from("path/to/config.toml");
/// let toml_file = std::fs::read(&file_path).unwrap();
/// let toml_file = String::from_utf8(toml_file).unwrap();
///
/// // parse bytes into TOML
/// let toml_file = toml_edit::Document::parse(toml_file).unwrap();
///
/// // parse TOML into RosenpassConfig
/// let (config, warnings) = RosenpassConfig::parse_from_toml(&toml_file, &file_path).unwrap();
///
/// // resolve a key's absolute file path
/// let relative_secret_key_path = config.our_keypair.secret_key_source.get_secret_key_path();
/// let absolute_secret_key_path = config.resolve_path(&relative_secret_key_path);
/// ```
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
    pub supported_protocol_versions: HashSet<ProtocolVersion>,

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
    // TODO: CommandLineArguments(ConfigSourceCli)
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
    Create {
        wg_listen_port: Option<u16>,
        wg_fwmark: Option<u16>,
    },

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

#[derive(Debug)]
pub struct OutputToFileConfig {
    /// whether the application should actually use this entry
    pub enabled: bool,

    pub output_file_path: PathBuf,

    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,
}

#[derive(Debug)]
pub struct WireguardConfig {
    /// whether the application should actually use this entry
    pub enabled: bool,

    /// references a [WgDeviceConfig] by [`WgDeviceConfig::name`]
    pub device_name: String,

    pub our_wireguard_keypair: WgKeypairSource,

    pub their_wireguard_public_key: PublicWgKeySource,

    pub wireguard_options: Option<PeerWireguardOptions>,

    /// deprecated, will be dropped in https://github.com/rosenpass/rosenpass/issues/1184
    pub exchange_command: Option<ExchangeCommand>,

    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,
}

#[derive(Debug)]
pub struct PeerWireguardOptions {
    pub preshared_key: PresharedKeySource,
    pub endpoint: SocketAddr,
    pub persistent_keepalive: usize,
    pub allowed_ips: Vec<IpCidr>,

    /// deprecated, will be dropped in https://github.com/rosenpass/rosenpass/issues/1183
    pub wg_extra_arguments: Vec<String>,
}

#[derive(Debug)]
pub struct ExchangeCommand {
    pub arguments: Vec<String>,
}
