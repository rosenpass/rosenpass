//! This module contains [`Error`], [`Warning`] and [`Issue`] which represent errors and warnings
//! about a certain Rosenpass configuration. They implement the [`std::error::Error`] trait using
//! the [`thiserror::Error`] derive macro.
//!
//! [`Issue`] is a simple sum type (enum) which can either hold an [`Error`] or a [`Warning`].

use std::path::PathBuf;
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
    #[error("secret key file has invalid content, expected secret key in file \"{0}\"")]
    OurSecretKeyFileHasInvalidContent(PathBuf),

    #[error("can not read public key file \"{0}\": file does not exist")]
    OurPublicKeyFileDoesNotExist(PathBuf),
    #[error("can not read public key file \"{0}\": {1}")]
    OurPublicKeyFileCanNotBeRead(PathBuf, std::io::Error),
    #[error("public key file has invalid content, expected public key in file \"{0}\"")]
    OurPublicKeyFileHasInvalidContent(PathBuf),

    // ============================== [[device]] ==============================
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

    // ============================== [[peer]] ==============================
    #[error("can not read public key file of peer \"{0}\" from \"{1}\": file does not exist")]
    PeerPublicKeyFileDoesNotExist(String, PathBuf),
    #[error("can not read public key file of peer \"{0}\" from \"{1}\": {2}")]
    PeerPublicKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error("TODO")]
    PeerPublicKeyFileHasInvalidContent(String, PathBuf),
    #[error("can not read preshared key file of peer \"{0}\" from \"{1}\": file does not exist")]
    PeerPskFileDoesNotExist(String, PathBuf),
    #[error("can not read preshared key file of peer \"{0}\" from \"{1}\": {2}")]
    PeerPskFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error("TODO")]
    PeerPskFileHasInvalidContent(String, PathBuf),

    /// TODO: this will most likely be found during parsing, already – or will it?
    #[error("Invalid OSK domain separation configuration for peer \"{0}\": {1}")]
    PeerHasInvalidOskDomainSeparator(String, anyhow::Error),

    // ========== output-to-file ==========
    #[error(
        "the keys exchanged with peer \"{0}\" are configured to be written to file \"{1}\" but that file can not be written to: {2}"
    )]
    PeerOutputToFileNotWritable(String, PathBuf, std::io::Error),

    // ========== wireguard ==========
    #[error("peer \"{0}\" uses wireguard device \"{1}\" but that device has not been defined")]
    EnabledPeerWireguardUsesUndefinedDevice(String, String),

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
    #[error("secret key file is globally readable: \"{0}\"")]
    OurSecretKeyFileIsGloballyReadable(PathBuf),

    #[error(
        "device \"{0}\" (managed by rosenpass) has wireguard secret key file which is globally readable \"{1}\""
    )]
    DeviceIsManagedByRosenpassButSecretKeyFileIsGloballyReadable(String, PathBuf),
    #[error(
        "device \"{0}\" (not managed by rosenpass) has wireguard secret key file which is globally readable \"{1}\""
    )]
    DeviceIsNotManagedByRosenpassAndSecretKeyFileIsGloballyReadable(String, PathBuf),

    #[error("wireguard secret key file is globally readable: \"{0}\"")]
    WireguardSecretKeyFileIsGloballyReadable(PathBuf),

    #[error("preshared key file is globally readable: \"{0}\"")]
    PresharedKeyFileIsGloballyReadable(PathBuf),

    #[error(
        "keys will be exchanged with peer \"{0}\" but the keys will not be used
    You should use at least the output-to-file or the wireguard option."
    )]
    PeerHasNoKeyUsage(String),

    #[error(
        "peer \"{0}\" has wireguard usage disabled, however, it it were enabled, it would use an undefined defined device \"{1}\""
    )]
    DisabledPeerUsesUndefinedDevice(String, String),

    #[error("can not check the validity of secret key (not implemented): \"{0}\"")]
    CanNotCheckValidityOfStaticKemSecretKey(PathBuf),
    #[error("can not check the validity of public key (not implemented): \"{0}\"")]
    CanNotCheckValidityOfStaticKemPublicKey(PathBuf),
}

/// an issue with the contents of a [`RosenpassConfig`]
///
/// This can either be a hard error (variant `Error`, containting an [`Error`]) or just a warning
/// (variant `Warning`, containing a [`Warning`]). The type implements the [`std::error::Error`]
/// trait using [`thiserror`] and outputs something like this:
/// ```text
/// error: can not read secret key file "/etc/rosenpass/our.pqsk": file does not exist
/// ```
///
/// You should use this type if you want to have collections of a mix of errors and warnings.
#[derive(Debug, Error)]
pub enum Issue {
    #[error("error: {0}")]
    Error(Error),
    #[error("warning: {0}")]
    Warning(Warning),
}
