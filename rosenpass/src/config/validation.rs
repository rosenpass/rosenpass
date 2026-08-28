//! TODO: document validation
//!

use super::{AsymmetricCipherType, FlatDeviceManagedByChoice};
use crate::internal::util::file::LoadValue;
use crate::protocol::basic_types::{SPk, SSk};
use std::{path::PathBuf, str::FromStr};
use thiserror::Error;

#[warn(dead_code)] // TODO: change this to deny(dead_code)
#[derive(Error, Debug)]
pub enum Error {
    // ============================== [rosenpass] ==============================
    #[error("can not read secret key file \"{0}\": file does not exist")]
    OurSecretKeyFileDoesNotExist(PathBuf),
    #[error("can not read secret key file \"{0}\": {1}")]
    OurSecretKeyFileCanNotBeRead(PathBuf, std::io::Error),
    #[error(
        "secret key file has invalid content, expected secret key for cipher {1} in file \"{0}\""
    )]
    OurSecretKeyFileHasInvalidContent(PathBuf, AsymmetricCipherType),

    #[error("can not read public key file: file does not exist: \"{0}\"")]
    OurPublicKeyFileDoesNotExist(PathBuf),
    #[error("TODO")]
    OurPublicKeyFileCanNotBeRead(PathBuf, std::io::Error),
    #[error("TODO")]
    OurPublicKeyFileHasInvalidContent(PathBuf, AsymmetricCipherType),

    // ============================== [[device]] ==============================
    #[error("device \"{0}\" is managed by rosenpass but has no wireguard secret key specified")]
    DeviceIsManagedByRosenpassButMissesWireguardSecretKey(String),
    #[error("device \"{0}\" is managed by rosenpass but has no wireguard public key specified")]
    DeviceIsManagedByRosenpassButMissesWireguardPublicKey(String),
    #[error("device \"{0}\" is managed by rosenpass but has no wireguard keypair specified")]
    DeviceIsManagedByRosenpassButMissesWireguardKeypair(String),
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
    #[error("TODO")]
    PeerPublicKeyFileDoesNotExist(String, PathBuf),
    #[error("TODO")]
    PeerPublicKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error("TODO")]
    PeerPublicKeyFileHasInvalidContent(String, PathBuf, AsymmetricCipherType),
    #[error("TODO")]
    PeerPskFileDoesNotExist(String, PathBuf),
    #[error("TODO")]
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
#[derive(Error, Debug)]
pub enum Warning {
    #[error("secret key file is globally readable: \"{0}\"")]
    OurSecretKeyFileIsGloballyReadable(PathBuf),
    #[error(
        "keys will be exchanged with peer \"{0}\" but the keys will not be used
    You should use at least the output-to-file or the wireguard option."
    )]
    PeerHasNoKeyUsage(String),

    #[error(
        "peer \"{0}\" has wireguard usage disabled, however, it it were enabled, it would use an undefined defined device \"{1}\""
    )]
    DisabledPeerUsesUndefinedDevice(String, String),
}

pub enum Issue {
    Error(Error),
    Warning(Warning),
}

pub struct ValidationRecipe {
    pub check_inconsistencies: bool,
    pub check_whether_files_exist: bool,
    pub check_file_permissions: bool,
    pub check_whether_external_binaries_behave: bool,
    pub check_key_file_contents: bool,
}
impl ValidationRecipe {
    pub fn nothing() -> ValidationRecipe {
        ValidationRecipe {
            check_inconsistencies: false,
            check_whether_files_exist: false,
            check_file_permissions: false,
            check_whether_external_binaries_behave: false,
            check_key_file_contents: false,
        }
    }
    pub fn all() -> ValidationRecipe {
        ValidationRecipe {
            check_inconsistencies: true,
            check_whether_files_exist: true,
            check_file_permissions: true,
            check_whether_external_binaries_behave: true,
            check_key_file_contents: true,
        }
    }
}
impl Default for ValidationRecipe {
    fn default() -> Self {
        ValidationRecipe::all()
    }
}

mod util {
    /// TODO: rename trait
    pub trait AttemptRead {
        fn attempt_read(&self) -> Result<(), std::io::Error>;
        fn attempt_write(&self) -> Result<(), std::io::Error>;
        // fn is_executable(&self) -> bool;
        fn behaves_like_wg_binary(&self) -> bool;
    }
    impl AttemptRead for std::path::PathBuf {
        fn attempt_read(&self) -> Result<(), std::io::Error> {
            let result = std::fs::OpenOptions::new()
                .read(true)
                .write(false)
                .open(self.clone());
            match result {
                Err(err) => Err(err),
                Ok(f) => {
                    std::mem::drop(f);
                    Ok(())
                }
            }
        }
        fn attempt_write(&self) -> Result<(), std::io::Error> {
            let result = std::fs::OpenOptions::new().write(true).open(self.clone());
            match result {
                Err(err) => Err(err),
                Ok(f) => {
                    std::mem::drop(f);
                    Ok(())
                }
            }
        }
        // fn is_executable(&self) -> bool {
        //     use std::os::unix::fs::PermissionsExt;
        //     self.metadata()
        //         .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
        //         .unwrap_or(false)
        // }
        fn behaves_like_wg_binary(&self) -> bool {
            unimplemented!()
        }
    }
}
pub use util::AttemptRead;

impl super::RosenpassConfig {
    #[rustfmt::skip]
    pub fn validate(&self, recipe: ValidationRecipe) -> Result<Vec<Warning>, Vec<Issue>> {
        let mut errors: Vec<Error> = Vec::new();
        let mut warnings: Vec<Warning> = Vec::new();
        // ============================== [rosenpass] ==============================
        for keyconfig in self.our_keys.iter() {
            if recipe.check_whether_files_exist && !keyconfig.secret_key_file.is_file() {
                errors.push(Error::OurSecretKeyFileDoesNotExist(keyconfig.secret_key_file.clone()));
            }
            if recipe.check_file_permissions && let Err(err) = keyconfig.secret_key_file.attempt_read() {
                errors.push(Error::OurSecretKeyFileCanNotBeRead(keyconfig.secret_key_file.clone(), err));
            }
            if recipe.check_key_file_contents {
                match keyconfig.cipher {
                    AsymmetricCipherType::McEliece460896 => {
                        errors.push(Error::UnimplementedFeature("checking the validity of McEliece460896 secret key files".to_string()));
                    }
                    AsymmetricCipherType::McEliece460896NistRound3 => {
                        if let Err(err) = SSk::load(&keyconfig.secret_key_file) {
                            errors.push(Error::OurSecretKeyFileHasInvalidContent(keyconfig.secret_key_file.clone(), keyconfig.cipher));
                        }
                    }
                }
            }
            if recipe.check_whether_files_exist && !keyconfig.public_key_file.is_file() {
                errors.push(Error::OurPublicKeyFileDoesNotExist(keyconfig.public_key_file.clone()));
            }
            if recipe.check_file_permissions && let Err(err) = keyconfig.public_key_file.attempt_read() {
                errors.push(Error::OurPublicKeyFileCanNotBeRead(keyconfig.public_key_file.clone(), err));
            }
            if recipe.check_key_file_contents {
                match keyconfig.cipher {
                    AsymmetricCipherType::McEliece460896 => {
                        errors.push(Error::UnimplementedFeature("checking the validity of McEliece460896 public key files".to_string()));
                    }
                    AsymmetricCipherType::McEliece460896NistRound3 => {
                        if let Err(err) = SPk::load(&keyconfig.public_key_file) {
                            errors.push(Error::OurPublicKeyFileHasInvalidContent(keyconfig.public_key_file.clone(), keyconfig.cipher));
                        }
                    }
                }
            }

            if recipe.check_inconsistencies {

                // #[cfg(feature = "experiment_api")]
                // TODO: check for NeitherOurKeypairNorApiConnections
            }
        }
        // ============================== [[device]] ==============================
        for device in self.devices.iter() {
            // wg binary
            if let Some(wg_path) = device.path_to_wg_binary.as_ref() {
                if recipe.check_whether_files_exist && !wg_path.is_file() {
                    errors.push(Error::DevicesWireguardBinaryDoesNotExist(device.name.clone(), wg_path.clone()));
                }
                // TODO: check whether executable
                if recipe.check_whether_external_binaries_behave && !wg_path.behaves_like_wg_binary() {
                    errors.push(Error::DevicesWireguardBinaryMisbehaves(device.name.clone(), wg_path.clone()));
                }
            }
            // managed by rosenpass
            if device.managed_by == FlatDeviceManagedByChoice::Rosenpass {
                match device.wireguard_keypair_if_managed_by_rosenpass {
                    None => errors.push(Error::DeviceIsManagedByRosenpassButMissesWireguardKeypair(device.name.clone())),
                    Some(_) => ()
                }
            }
        }
        // ============================== [[peer]] ==============================
        for peer in self.peers.iter() {
            // TODO: name
            // TODO: algorithm
            // public key file
            if recipe.check_whether_files_exist && !peer.public_key_file.is_file() {
                errors.push(Error::PeerPublicKeyFileDoesNotExist(peer.name.clone(), peer.public_key_file.clone()));
            }
            if recipe.check_file_permissions && let Err(err) = peer.public_key_file.attempt_read() {
                errors.push(Error::PeerPublicKeyFileCanNotBeRead(peer.name.clone(), peer.public_key_file.clone(), err))
            }
            // TODO: endpoint
            // preshared key file
            if let Some(psk) = peer.preshared_key_file.as_ref() {
                if recipe.check_whether_files_exist && !psk.is_file() {
                    errors.push(Error::PeerPskFileDoesNotExist(peer.name.clone(), psk.clone()))
                }
                if recipe.check_file_permissions && let Err(err) = psk.attempt_read() {
                    errors.push(Error::PeerPskFileCanNotBeRead(peer.name.clone(), psk.clone(), err));
                }
            }
            // osk domain separator
            if recipe.check_inconsistencies && let Err(err) = peer.osk_domain_separator.validate() {
                errors.push(Error::PeerHasInvalidOskDomainSeparator(peer.name.clone(), err));
            }
            // output to file
            if let Some(output_to_file) = peer.output_to_file.as_ref() {
                if output_to_file.enabled {
                    if recipe.check_file_permissions && let Err(err) = output_to_file.output_file_path.attempt_write() {
                        errors.push(Error::PeerOutputToFileNotWritable(peer.name.clone(), output_to_file.output_file_path.clone(), err));
                    }
                }
            }
            // wireguard
            if let Some(wireguard) = peer.wireguard.as_ref(){
                // device
                if recipe.check_inconsistencies && self.devices.iter().find(|d| d.name == wireguard.device_name).is_none() {
                    if wireguard.enabled {
                        errors.push(Error::EnabledPeerWireguardUsesUndefinedDevice(peer.name.clone(), wireguard.device_name.clone()));
                    }
                    else {
                        warnings.push(Warning::DisabledPeerUsesUndefinedDevice(peer.name.clone(), wireguard.device_name.clone()));
                    }
                }
                // wg binary
                if let Some(wg_binary) = wireguard.wg_binary_path.as_ref()  {
                    if recipe.check_whether_files_exist && !wg_binary.is_file() {
                            errors.push(Error::PeersWireguardBinaryDoesNotExist(peer.name.clone(), wg_binary.clone()))
                    }
                    // TODO:
                    // if recipe.check_file_permissions && !wg_binary.is_executable() {
                    //     errors.push(Error::PeersWireguardBinaryIsNotExecutable(peer.name, wg_binary.clone()));
                    // }
                    if recipe.check_whether_external_binaries_behave && !wg_binary.behaves_like_wg_binary() {
                        errors.push(Error::PeersWireguardBinaryMisbehaves(peer.name.clone(), wg_binary.clone()));
                    }
                }
                // TODO: if managed by rosenpass
            }
        }
        // ============================== other ==============================
        if recipe.check_whether_external_binaries_behave && !PathBuf::from_str("wg").unwrap().behaves_like_wg_binary() {
            errors.push(Error::DefaultWireguardBinaryMisbehaves);
        }
        unimplemented!("warnings")
    }
}
