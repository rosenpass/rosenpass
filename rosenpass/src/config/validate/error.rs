//! This module contains [`enum@Error`], [`Warning`] and [`Issue`] which represent errors and warnings
//! about a certain Rosenpass configuration. They implement the [`std::error::Error`] trait using
//! the [`thiserror::Error`] derive macro.
//!
//! [`Issue`] is a simple sum type (enum) which can either hold an [`enum@Error`] or a [`Warning`].

use crate::protocol::ProtocolVersion;
use anstyle::AnsiColor;
use std::{fmt::Display, path::PathBuf};
use thiserror::Error;

// allow unused import because the import is actually used in the doc comment which clippy does not
// identify correctly
#[allow(unused_imports)]
use super::RosenpassConfig;

/// an error in the contents of a [`RosenpassConfig`]
///
/// This indicates a hard error and the application will not run. There is no guarantee about the
/// stability of this type. Variants might get added or removed. It implements the
/// [`std::error::Error`] using [`thiserror`] so that it prints nice user-facing error messages.
#[warn(dead_code)] // TODO: change this to deny(dead_code)
#[derive(Error, Debug)]
pub enum Error {
    // ============================== [rosenpass] ==============================
    #[error("can not read secret key file \"{0}\": file does not exist")]
    OurSecretKeyFileDoesNotExist(PathBuf),
    #[error("can not read secret key file \"{0}\": {1}")]
    OurSecretKeyFileCanNotBeRead(PathBuf, std::io::Error),
    #[error("secret key file has invalid content, expected secret key in file \"{0}\": {1}")]
    OurSecretKeyFileHasInvalidContent(PathBuf, anyhow::Error),

    #[error("can not read public key file \"{0}\": file does not exist")]
    OurPublicKeyFileDoesNotExist(PathBuf),
    #[error("can not read public key file \"{0}\": {1}")]
    OurPublicKeyFileCanNotBeRead(PathBuf, std::io::Error),
    #[error("public key file has invalid content, expected public key in file \"{0}\": {1}")]
    OurPublicKeyFileHasInvalidContent(PathBuf, anyhow::Error),

    // ============================== [[wireguard-devices]] ==============================
    #[error("duplicate name \"{0}\" among enabled WireGuard devices")]
    DuplicateDeviceName(String),

    #[error("device \"{0}\" is managed by rosenpass but has no wireguard secret key specified")]
    DeviceIsManagedByRosenpassButMissesWireguardSecretKey(String),
    #[error("device \"{0}\" is managed by rosenpass but has no wireguard public key specified")]
    DeviceIsManagedByRosenpassButMissesWireguardPublicKey(String),
    #[error("device \"{0}\" is managed by rosenpass but has no wireguard keypair specified")]
    DeviceIsManagedByRosenpassButMissesWireguardKeypair(String),

    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard secret key file \"{1}\": file does not exist"
    )]
    DeviceIsManagedByRosenpassButSecretKeyFileDoesNotExist(String, PathBuf),
    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard secret key file \"{1}\": {2}"
    )]
    DeviceIsManagedByRosenpassButSecretKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "device \"{0}\" is managed by rosenpass but wireguard secret key file \"{1}\" has invalid content"
    )]
    DeviceIsManagedByRosenpassButSecretKeyFileHasInvalidContent(String, PathBuf),
    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard public key file \"{1}\": file does not exist"
    )]
    DeviceIsManagedByRosenpassButPublicKeyFileDoesNotExist(String, PathBuf),
    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard public key file \"{1}\": {2}"
    )]
    DeviceIsManagedByRosenpassButPublicKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "device \"{0}\" is managed by rosenpass but wireguard public key file \"{1}\" has invalid content"
    )]
    DeviceIsManagedByRosenpassButPublicKeyFileHasInvalidContent(String, PathBuf),

    #[error(
        "a custom wg binary has been specified for device \"{0}\" but the binary file does not exist: \"{1}\""
    )]
    DevicesWireguardBinaryDoesNotExist(String, PathBuf),
    #[error(
        "a custom wg binary has been specified for device \"{0}\" but the binary file is not executable: \"{1}\""
    )]
    DevicesWireguardBinaryIsNotExecutable(String, PathBuf),
    #[error(
        "a custom wg binary has been specified for device \"{0}\" but the binary file does not behave like a valid wg executable: \"{1}\""
    )]
    DevicesWireguardBinaryMisbehaves(String, PathBuf),

    // ============================== [[peers]] ==============================
    #[error("duplicate name \"{0}\" among enabled peers")]
    DuplicatePeerName(String),

    #[error("can not read public key file of peer \"{0}\" from \"{1}\": file does not exist")]
    PeerPublicKeyFileDoesNotExist(String, PathBuf),
    #[error("can not read public key file of peer \"{0}\" from \"{1}\": {2}")]
    PeerPublicKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "public key file of peer \"{0}\" has invalid content, expected public key in file \"{1}\": {2}"
    )]
    PeerPublicKeyFileHasInvalidContent(String, PathBuf, anyhow::Error),

    #[error("peer \"{0}\" has an invalid endpoint \"{1}\": {2}")]
    InvalidPeerEndpoint(String, String, std::io::Error),

    #[error("can not read preshared key file of peer \"{0}\" from \"{1}\": file does not exist")]
    PeerPskFileDoesNotExist(String, PathBuf),
    #[error("can not read preshared key file of peer \"{0}\" from \"{1}\": {2}")]
    PeerPskFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "preshared key file with peer \"{0}\" has invalid content, expected PSK in file \"{1}\": {2}"
    )]
    PeerPskFileHasInvalidContent(String, PathBuf, anyhow::Error),

    /// TODO: this will most likely be found during parsing, already – or will it?
    #[error("Invalid OSK domain separation configuration for peer \"{0}\": {1}")]
    PeerHasInvalidOskDomainSeparator(String, anyhow::Error),

    // ========== output-to-file ==========
    #[error(
        "the keys exchanged with peer \"{0}\" are configured to be written to file \"{1}\" but that file can not be written to: {2}"
    )]
    PeerOutputToFileNotWritable(String, PathBuf, std::io::Error),
    #[error(
        "Invalid OSK domain separation configuration for peer \"{0}\" for output-to-file option: {1}"
    )]
    PeerHasInvalidOskDomainSeparatorInOutfile(String, anyhow::Error),

    // ========== wireguard ==========
    #[error("peer \"{0}\" uses wireguard device \"{1}\" but that device has not been defined")]
    EnabledPeerWireguardUsesUndefinedDevice(String, String),

    // our WG keypair
    #[error(
        "can not read our secret WireGuard key file \"{1}\" used with peer \"{0}\": file does not exist"
    )]
    PeerWireguardOurSecretKeyFileDoesNotExist(String, PathBuf),
    #[error("can not read our secret WireGuard key file \"{1}\" used with peer \"{0}\": {2}")]
    PeerWireguardOurSecretKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "our WireGuard secret key used with peer \"{0}\" file has invalid content, expected WireGuard secret key in file \"{1}\": {2}"
    )]
    PeerWireguardOurSecretKeyFileHasInvalidContent(String, PathBuf, anyhow::Error),

    #[error(
        "can not read our WireGuard public key file \"{1}\" used with peer \"{0}\": file does not exist"
    )]
    PeerWireguardOurPublicKeyFileDoesNotExist(String, PathBuf),
    #[error("can not read our WireGuard public key file \"{1}\" used with peer \"{0}\": {2}")]
    PeerWireguardOurPublicKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "our WireGuard public key file \"{1}\" used with peer \"{0}\" has invalid content, expected WireGuard public key in file \"{1}\": {2}"
    )]
    PeerWireguardOurPublicKeyFileHasInvalidContent(String, PathBuf, anyhow::Error),
    #[error(
        "our WireGuard public key (specified as base-encoded string) used with peer \"{0}\" has invalid content, expected WireGuard public key, base64-encoded"
    )]
    PeerWireguardOurPublicKeyInlineHasInvalidContent(String, anyhow::Error),

    // their WG public key
    #[error(
        "peer \"{0}\" WireGuard public key file \"{1}\" has invalid content, expected WireGuard public key in file \"{1}\": {2}"
    )]
    PeerWireguardTheirPublicKeyFileHasInvalidContent(String, PathBuf, anyhow::Error),
    #[error(
        "peer \"{0}\"\'s WireGuard public key (specified as base-encoded string) has invalid content, expected WireGuard public key, base64-encoded: {1}"
    )]
    PeerWireguardTheirPublicKeyInlineHasInvalidContent(String, anyhow::Error),

    // other WG stuff
    #[error(
        "peer \"{0}\" uses {1} and has a wireguard config, but our WireGuard public key is not set"
    )]
    PeerNeedsToBindToOurWgPubkey(String, ProtocolVersion),

    #[error(
        "a custom wg binary has been specified for peer \"{0}\" but the binary file does not exist: \"{1}\""
    )]
    PeersWireguardBinaryDoesNotExist(String, PathBuf),
    #[error(
        "a custom wg binary has been specified for peer \"{0}\" but the binary file is not executable: \"{1}\""
    )]
    PeersWireguardBinaryIsNotExecutable(String, PathBuf),
    #[error(
        "a custom wg binary has been specified for peer \"{0}\" but the binary file does not behave like a valid wg executable: \"{1}\""
    )]
    PeersWireguardBinaryMisbehaves(String, PathBuf),

    // TODO: more errors here

    // ============================== other ==============================
    #[cfg(feature = "experiment_api")]
    #[error(
        "neither a keypair nor some API connections are specified
    Specify a server keypair or some API connections to configure the keypair with.
    Without a keypair, rosenpass can not operate."
    )]
    NeitherOurKeypairNorApiConnections,
    #[error("could not find \"wg\" binary")]
    DefaultWireguardBinaryDoesNotExist,
    #[error("\"wg\" binary misbehaves")]
    DefaultWireguardBinaryMisbehaves,

    #[error("not yet implemented: {0}")]
    UnimplementedFeature(String),
}

/// a warning about the contents of a [`RosenpassConfig`]
///
/// This is not hard error and will not prevent the application from running but it indicates to the
/// user that they might want to check their configuration again.
/// It implements the [`std::error::Error`] using [`thiserror`] so that it prints nice user-facing
/// error messages.
#[derive(Error, Debug)]
pub enum Warning {
    // ============================== [rosenpass] ==============================
    #[error("secret key file is globally readable: \"{0}\"")]
    OurSecretKeyFileIsGloballyReadable(PathBuf),

    // ============================== [[wireguard-devices]] ==============================
    #[error("WireGuard device \"{0}\" is disabled")]
    DeviceIsDisabled(String),

    #[error(
        "WireGuard device has very long name ({0} characters while the recommended maximum length is {1} characters): WireGuard device is named \"{0}\""
    )]
    DeviceHasVeryLongName(String, usize, usize),

    // ============================== [[peers]] ==============================
    #[error(
        "peer has very long name ({0} characters while the recommended maximum length is {1} characters): peer is named \"{0}\""
    )]
    PeerHasVeryLongName(String, usize, usize),

    #[error("peer \"{0}\" is disabled")]
    PeerIsDisabled(String),

    #[error("PSK file \"{1}\" with peer \"{0}\" is globally readable")]
    PeerPskFileIsGloballyReadable(String, PathBuf),

    // ========== output-to-file ==========
    #[error("peer \"{0}\" has an output-to-file configuration but it is disabled")]
    PeerOutputToFileIsDisabled(String),

    // ========== wireguard ==========
    #[error("peer \"{0}\" has a WireGuard configuration but it is disabled")]
    PeerWireGuardIsDisabled(String),

    #[error("our WireGuard secret key file used with peer \"{0}\" is globally readable: \"{1}\"")]
    PeerWireguardOurSecretKeyFileIsGloballyReadable(String, PathBuf),

    // ========== other ==========
    #[error(
        "keys will be exchanged with peer \"{0}\" but the keys will not be used
    You should use at least the output-to-file or the wireguard option."
    )]
    PeerHasNoKeyUsage(String),
}

/// an issue with the contents of a [`RosenpassConfig`]
///
/// This can either be a hard error (variant `Error`, containting an [`enum@Error`]) or just a warning
/// (variant `Warning`, containing a [`Warning`]). The type implements the [`std::error::Error`]
/// trait using [`thiserror`] and outputs something like this:
/// ```text
/// error: can not read secret key file "/etc/rosenpass/our.pqsk": file does not exist
/// ```
///
/// You should use this type if you want to have collections of a mix of errors and warnings.
#[derive(Debug)]
pub enum Issue {
    Error(Error),
    Warning(Warning),
}

impl Display for Issue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let error_style = anstyle::Style::new()
            .fg_color(Some(AnsiColor::Red.into()))
            .bold();
        let warning_style = anstyle::Style::new()
            .fg_color(Some(AnsiColor::Yellow.into()))
            .bold();
        match &self {
            Self::Error(e) => {
                write!(f, "{error_style}error: {error_style:#}")?;
                writeln!(f, "{e}")?;
            }
            Self::Warning(w) => {
                write!(f, "{warning_style}warning: {warning_style:#}")?;
                writeln!(f, "{w}")?;
            }
        }
        Ok(())
    }
}
impl std::error::Error for Issue {}
impl From<Error> for Issue {
    fn from(value: Error) -> Self {
        Self::Error(value)
    }
}
impl From<Warning> for Issue {
    fn from(value: Warning) -> Self {
        Self::Warning(value)
    }
}
impl Issue {
    pub fn as_error(&self) -> Option<&Error> {
        match &self {
            Self::Warning(_) => None,
            Self::Error(e) => Some(e),
        }
    }
    pub fn to_error(self) -> Option<Error> {
        match self {
            Self::Warning(_) => None,
            Self::Error(e) => Some(e),
        }
    }
    pub fn as_warning(&self) -> Option<&Warning> {
        match &self {
            Self::Warning(w) => Some(w),
            Self::Error(_) => None,
        }
    }
    pub fn to_warning(self) -> Option<Warning> {
        match self {
            Self::Warning(w) => Some(w),
            Self::Error(_) => None,
        }
    }
}
