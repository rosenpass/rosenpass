use core::net::SocketAddr;
use log::LevelFilter;
use serde::{Deserialize, Serialize};
use std::{fmt::Display, path::PathBuf};

use crate::{oldconfig::RosenpassPeerOskDomainSeparator, protocol::ProtocolVersion};

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

    pub our_keys: Vec<OurKeyConfig>,

    pub protocol_version: ProtocolVersion,

    /// TODO: also support [crate::oldconfig::Verbosity]
    /// TODO: implement default
    pub log_level: LevelFilter,
    pub logging_output_file: Option<PathBuf>,

    /// Location of the API listen sockets
    #[cfg(feature = "experiment_api")]
    pub api: crate::api::config::ApiConfig,

    pub devices: Vec<DeviceConfig>,
    pub peers: Vec<PeerConfig>,
}
// ============================== [rosenpass] ==============================
#[derive(Debug)]
pub struct OurKeyConfig {
    pub cipher: AsymmetricCipherType,
    /// TODO: use [crate::oldconfig::Keypair] instead?
    pub secret_key_file: PathBuf,
    pub public_key_file: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum AsymmetricCipherType {
    #[serde(rename = "mceliece460896")]
    McEliece460896,
    #[serde(rename = "mceliece460896nistround3")]
    McEliece460896NistRound3,
}
impl Display for AsymmetricCipherType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            serde_json::to_string(&self)
                .expect("can not serialize AsymmetricCipherType – should be unreachable")
        )
    }
}
// ============================== [[device]] ==============================
#[derive(Debug)]
pub struct DeviceConfig {
    pub name: String,
    pub managed_by: DeviceManagedByChoice,
    pub path_to_wg_binary: Option<PathBuf>,
}
#[derive(Debug)]
pub enum DeviceManagedByChoice {
    Rosenpass {
        wireguard_secret_key_file: PathBuf,
        wireguard_public_key_file: PathBuf,
    },
    Wireguard,
}

/// flat version of [DeviceManagedByChoice]
///
/// used as an intermediate result during parsing
#[derive(Debug)]
pub enum FlatDeviceManagedByChoice {
    Rosenpass,
    Wireguard,
}

// ============================== [[peer]] ==============================
#[derive(Debug)]
pub struct PeerConfig {
    pub name: String,
    pub algorithm: CryptoAlgorithmsChoice,
    pub public_key_file: PathBuf,
    pub endpoint: SocketAddr,
    pub preshared_key_file: Option<PathBuf>,

    /// Allows using a custom domain separator
    pub osk_domain_separator: RosenpassPeerOskDomainSeparator,

    pub output_to_file: Option<OutputToFileConfig>,
    pub wireguard: Option<WireguardConfig>,
}
#[derive(Debug)]
pub struct CryptoAlgorithmsChoice {
    pub asymmetric_cipher: AsymmetricCipherType,
    pub kem: KemAlgorithmChoice,
    pub symmetric_cipher: SymmetricCipherChoice,
    pub hash: HashAlgorithmChoice,
}
#[derive(Debug)]
pub enum KemAlgorithmChoice {
    Kyber512,
}
#[derive(Debug)]
pub enum SymmetricCipherChoice {
    ChaChaPoly1305,
}
#[derive(Debug)]
pub enum HashAlgorithmChoice {
    Blake2s,
}

#[derive(Debug)]
pub struct OutputToFileConfig {
    pub enabled: bool,
    pub output_file_path: PathBuf,
}
#[derive(Debug)]
pub struct WireguardConfig {
    pub enabled: bool,
    pub device: String,
    pub wg_binary_path: Option<PathBuf>,
    pub if_managed_by_rosenpass: AdditionalWireguardConfigIfInterfaceManagedByRosenpass,
}
#[derive(Debug)]
pub struct AdditionalWireguardConfigIfInterfaceManagedByRosenpass {
    pub wireguard_public_key_file: PathBuf,
    pub persistent_keep_alive_interval_in_seconds: Option<usize>,
    pub allowed_ips: Option<Vec<String>>, // TODO: make this a CIDR
    pub wg_extra_arguments: Vec<String>,
}
