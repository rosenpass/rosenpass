use super::parse_from_toml::ParseWarning as TomlParseWarning;
use crate::{
    oldconfig::{RosenpassPeerOskDomainSeparator, Verbosity},
    protocol::ProtocolVersion,
};
use cidr::IpCidr;
pub use core::net::SocketAddr;
use std::{collections::HashSet, marker::PhantomData, path::PathBuf};
use tstr::{IsTStr, TS};

/// Configuration for Rosenpass
///
/// TODO: parse this manually with `toml_edit` – ask Ilka <ilka@rosenpass.eu> for experience
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
    pub api: crate::api::config::ApiConfig,

    pub wireguard_devices: Vec<WgDeviceConfig>,
    pub peers: Vec<PeerConfig>,

    pub parsed_from: ConfigSource,
}
// ============================== [rosenpass] ==============================
/// a source a keypair consisting of one secret and one public key
///
/// - the secret key is always read from disk ([`KeyFromDisk`])
/// - the public key can be read from different sources (parameter `P`, e.g. [`KeyFromDisk`] or
///   [`KeyFromDiskOrB64EncodedString`])
/// - if keys are read from a directory, the parameters `SFN` (secret file name) and `PFN` (public
///   file name) specify the file inside the directory which should be read
///
/// TODO: more documentation
#[derive(Debug)]
pub struct Keypair<S: SecretKeySource, P: PublicKeySource> {
    pub secret_key_source: S,
    pub public_key_source: P,
}
#[derive(Debug)]
pub enum KeyFromDiskInner {
    File(PathBuf),
    Directory(PathBuf),
}
#[derive(Debug)]
pub struct KeyFromDisk<FN: IsTStr> {
    pub inner: KeyFromDiskInner,
    _marker: PhantomData<FN>,
}
#[derive(Debug)]
pub enum KeyFromDiskOrB64EncodedStringInner {
    File(PathBuf),
    Directory(PathBuf),
    Base64EncodedString(String),
}
#[derive(Debug)]
pub struct KeyFromDiskOrB64EncodedString<FN: IsTStr> {
    pub inner: KeyFromDiskOrB64EncodedStringInner,
    _marker: PhantomData<FN>,
}
pub type PqKeypairSource = Keypair<SecretPqKeySource, PublicPqKeySource>;
pub type SecretPqKeySource = KeyFromDisk<TS!("pqsk")>;
pub type PublicPqKeySource = KeyFromDisk<TS!("pqsk")>;
pub type WgKeypairSource = Keypair<SecretWgKeySource, PublicWgKeySource>;
pub type SecretWgKeySource = KeyFromDisk<TS!("wgsk")>;
pub type PublicWgKeySource = KeyFromDiskOrB64EncodedString<TS!("wgpk")>;

// TODO: stuff these traits into submodule
pub trait HasInnerType: Sized {
    type InnerType;
}
impl<FN: IsTStr> HasInnerType for KeyFromDisk<FN> {
    type InnerType = KeyFromDiskInner;
}
impl<FN: IsTStr> HasInnerType for KeyFromDiskOrB64EncodedString<FN> {
    type InnerType = KeyFromDiskOrB64EncodedStringInner;
}
pub trait NewFromInner: HasInnerType + From<Self::InnerType> {
    fn new(inner: Self::InnerType) -> Self {
        Self::from(inner)
    }
}
impl<T> NewFromInner for T where T: HasInnerType + From<T::InnerType> {}
impl<FN: IsTStr> From<KeyFromDiskInner> for KeyFromDisk<FN> {
    fn from(value: KeyFromDiskInner) -> Self {
        KeyFromDisk {
            inner: value,
            _marker: Default::default(),
        }
    }
}
impl<FN: IsTStr> From<KeyFromDiskOrB64EncodedStringInner> for KeyFromDiskOrB64EncodedString<FN> {
    fn from(value: KeyFromDiskOrB64EncodedStringInner) -> Self {
        KeyFromDiskOrB64EncodedString {
            inner: value,
            _marker: Default::default(),
        }
    }
}

pub trait SecretKeySource {
    fn get_key_path(&self) -> PathBuf;
    // TODO:
    // fn get_key(&self, length: usize) -> Self::GetKeyOutput;
}
impl<FN: IsTStr> SecretKeySource for KeyFromDisk<FN> {
    fn get_key_path(&self) -> PathBuf {
        match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
        }
    }
}
pub trait PublicKeySource {
    type GetPathOutput;
    type GetInlineOutput;
    fn get_key_path(&self) -> Self::GetPathOutput;
    fn get_inline_key(&self) -> Self::GetInlineOutput;
    // TODO:
    // fn get_key(&self, length: usize) -> Self::GetKeyOutput;
}
impl<FN: IsTStr> PublicKeySource for KeyFromDisk<FN> {
    type GetPathOutput = PathBuf;
    type GetInlineOutput = !;
    fn get_key_path(&self) -> Self::GetPathOutput {
        match &self.inner {
            KeyFromDiskInner::File(file) => file.clone(),
            KeyFromDiskInner::Directory(dir) => dir.join(FN::STR),
        }
    }
    fn get_inline_key(&self) -> Self::GetInlineOutput {
        unimplemented!("this key is always read from disk")
    }
}
impl<FN: IsTStr> PublicKeySource for KeyFromDiskOrB64EncodedString<FN> {
    type GetPathOutput = Option<PathBuf>;
    type GetInlineOutput = Option<String>;
    fn get_key_path(&self) -> Self::GetPathOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(file) => Some(file.clone()),
            KeyFromDiskOrB64EncodedStringInner::Directory(dir) => Some(dir.join(FN::STR)),
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(_raw) => None,
        }
    }
    fn get_inline_key(&self) -> Self::GetInlineOutput {
        match &self.inner {
            KeyFromDiskOrB64EncodedStringInner::File(_file) => None,
            KeyFromDiskOrB64EncodedStringInner::Directory(_dir) => None,
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(raw) => Some(raw.clone()),
        }
    }
}

#[derive(Debug)]
pub enum ConfigSource {
    TomlFile(ConfigSourceTomlFile),
    // CommandLineArguments(ConfigSourceCli)
}

#[derive(Debug)]
pub struct ConfigSourceTomlFile {
    /// path to the TOML file which has been parsed
    pub file_path: PathBuf,

    /// the complete TOML document which has been parsed
    pub document: toml_edit::Document<String>,

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
// ============================== [[device]] ==============================
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

// ============================== [[peer]] ==============================
#[derive(Debug)]
pub struct PeerConfig {
    /// cosmetic name of the peer
    pub name: String,

    /// whether the application should actually use this entry
    pub enabled: bool,

    /// public key of the peer (static KEM)
    pub their_public_key: PublicPqKeySource,

    /// endpoint of the peer's Rosenpass application
    pub endpoint: SocketAddr,

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
