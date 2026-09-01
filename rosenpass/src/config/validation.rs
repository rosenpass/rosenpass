//! TODO: document validation
//!

use super::{FlatDeviceManagedByChoice, StaticKemChoice};
use crate::internal::util::file::LoadValue;
use crate::protocol::basic_types::{SPk, SSk};
use std::path::PathBuf;
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
    OurSecretKeyFileHasInvalidContent(PathBuf, StaticKemChoice),

    #[error("can not read public key file \"{0}\": file does not exist")]
    OurPublicKeyFileDoesNotExist(PathBuf),
    #[error("can not read public key file \"{0}\": {1}")]
    OurPublicKeyFileCanNotBeRead(PathBuf, std::io::Error),
    #[error(
        "public key file has invalid content, expected public key for cipher {1} in file \"{0}\""
    )]
    OurPublicKeyFileHasInvalidContent(PathBuf, StaticKemChoice),

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
        "device \"{0}\" is managed by rosenpass but can not read wireguard secret key file \"{1}\": {2}"
    )]
    DeviceIsManagedByRosenpassButSecretKeyFileHasInvalidContent(String, PathBuf, StaticKemChoice),
    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard public key file \"{1}\": file does not exist"
    )]
    DeviceIsManagedByRosenpassButPublicKeyFileDoesNotExist(String, PathBuf),
    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard public key file \"{1}\": {2}"
    )]
    DeviceIsManagedByRosenpassButPublicKeyFileCanNotBeRead(String, PathBuf, std::io::Error),
    #[error(
        "device \"{0}\" is managed by rosenpass but can not read wireguard public key file \"{1}\": {2}"
    )]
    DeviceIsManagedByRosenpassButPublicKeyFileHasInvalidContent(String, PathBuf, StaticKemChoice),

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
    PeerPublicKeyFileHasInvalidContent(String, PathBuf, StaticKemChoice),
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

    #[error("can not check the validity of {1} secret key (not implemented): \"{0}\"")]
    CanNotCheckValidityOfStaticKemSecretKey(PathBuf, StaticKemChoice),
    #[error("can not check the validity of {1} public key (not implemented): \"{0}\"")]
    CanNotCheckValidityOfStaticKemPublicKey(PathBuf, StaticKemChoice),
}
#[derive(Debug, Error)]
pub enum Issue {
    #[error("error: {0}")]
    Error(Error),
    #[error("warning: {0}")]
    Warning(Warning),
}

#[derive(Debug)]
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
    use anyhow::anyhow;
    use rustix::path::Arg;

    /// TODO: rename trait
    pub trait AttemptRead {
        fn attempt_read(&self) -> Result<(), std::io::Error>;
        fn is_world_readable(&self) -> Option<bool>;
        fn attempt_write(&self) -> Result<(), std::io::Error>;
        fn is_executable(&self) -> bool;
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
        #[cfg(not(any(target_os = "linux", target_os = "windows")))]
        fn is_world_readable(&self) -> Option<bool> {
            // TODO: implement
            None
        }
        #[cfg(target_os = "linux")]
        fn is_world_readable(&self) -> Option<bool> {
            use std::os::unix::fs::PermissionsExt;
            self.metadata()
                .ok()
                .map(|metadata| metadata.permissions().mode() & 0o004 != 0)
        }
        #[cfg(target_os = "windows")]
        fn is_world_readable(&self) -> Option<bool> {
            None

            // TODO: implement this for windows
            // example implementation:
            // use std::ffi::c_void;
            // use std::mem::{size_of, zeroed};
            // use std::os::windows::ffi::OsStrExt;
            // use std::ptr::null_mut;

            // use windows_sys::Win32::{
            //     Foundation::{ERROR_SUCCESS, LocalFree},
            //     Security::{
            //         ACL,
            //         Authorization::{
            //             BuildTrusteeWithSidW, GetEffectiveRightsFromAclW, GetNamedSecurityInfoW,
            //             SE_FILE_OBJECT, TRUSTEE_W,
            //         },
            //         CreateWellKnownSid, DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR, PSID,
            //         SECURITY_MAX_SID_SIZE, WinWorldSid,
            //     },
            //     Storage::FileSystem::FILE_READ_DATA,
            // };

            // // GetNamedSecurityInfoW erwartet einen NUL-terminierten UTF-16-Pfad.
            // let path_wide: Vec<u16> = path
            //     .as_os_str()
            //     .encode_wide()
            //     .chain(std::iter::once(0))
            //     .collect();

            // let mut dacl: *mut ACL = null_mut();
            // let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();

            // let result = unsafe {
            //     GetNamedSecurityInfoW(
            //         path_wide.as_ptr(),
            //         SE_FILE_OBJECT,
            //         DACL_SECURITY_INFORMATION,
            //         null_mut(),
            //         null_mut(),
            //         &mut dacl,
            //         null_mut(),
            //         &mut security_descriptor,
            //     )
            // };

            // if result != ERROR_SUCCESS {
            //     return Err(std::io::Error::from_raw_os_error(result as i32));
            // }

            // // GetNamedSecurityInfoW alloziert den Security Descriptor mit LocalAlloc.
            // struct SecurityDescriptorGuard(PSECURITY_DESCRIPTOR);

            // impl Drop for SecurityDescriptorGuard {
            //     fn drop(&mut self) {
            //         if !self.0.is_null() {
            //             unsafe {
            //                 LocalFree(self.0.cast::<c_void>());
            //             }
            //         }
            //     }
            // }

            // let _guard = SecurityDescriptorGuard(security_descriptor);

            // // Keine DACL / NULL DACL bedeutet uneingeschränkten Zugriff.
            // if dacl.is_null() {
            //     return Ok(true);
            // }

            // // Buffer für die Well-Known-SID "Everyone" (S-1-1-0).
            // // usize sorgt nebenbei für ausreichendes Alignment.
            // const SID_WORDS: usize =
            //     (SECURITY_MAX_SID_SIZE as usize + size_of::<usize>() - 1) / size_of::<usize>();

            // let mut sid_buffer = [0usize; SID_WORDS];
            // let mut sid_size = size_of::<[usize; SID_WORDS]>() as u32;
            // let everyone_sid: PSID = sid_buffer.as_mut_ptr().cast();

            // if unsafe { CreateWellKnownSid(WinWorldSid, null_mut(), everyone_sid, &mut sid_size) }
            //     == 0
            // {
            //     return Err(std::io::Error::last_os_error());
            // }

            // let mut trustee: TRUSTEE_W = unsafe { zeroed() };

            // unsafe {
            //     BuildTrusteeWithSidW(&mut trustee, everyone_sid);
            // }

            // let mut rights = 0u32;

            // let result = unsafe { GetEffectiveRightsFromAclW(dacl, &mut trustee, &mut rights) };

            // if result != ERROR_SUCCESS {
            //     return Err(std::io::Error::from_raw_os_error(result as i32));
            // }

            // Some(rights & FILE_READ_DATA != 0)
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
        fn is_executable(&self) -> bool {
            use rustix::fs::{Access, AtFlags, CWD, accessat};
            accessat(CWD, self, Access::EXEC_OK, AtFlags::EACCESS).is_ok()

            // unix-specific implementation
            // use std::os::unix::fs::PermissionsExt;
            // self.metadata()
            //     .map(|metadata| metadata.permissions().mode() & 0o111 != 0)
            //     .unwrap_or(false)
        }
        fn behaves_like_wg_binary(&self) -> bool {
            let implementation = || -> Result<(), anyhow::Error> {
                let command_name = self.to_string_lossy();
                if !std::process::Command::new(self)
                    .arg("--version")
                    .output()?
                    .stdout
                    .to_string_lossy()
                    .to_lowercase()
                    .contains("wireguard")
                {
                    return Err(anyhow!(
                        "output generated with `{command_name} --version` does not contain the string `wireguard`"
                    ));
                }
                Ok(())
                // TODO: check if `wg set` is available
            };
            implementation().is_ok() // TODO: return error?
        }
    }
}
pub use util::AttemptRead;

macro_rules! validate_keypair {
    ($secret_path: expr, $public_path: expr, $warnings: ident, $errors: ident, $recipe: ident, $static_kem_choice: expr,
        $context: expr,
        $SecretKeyFileDoesNotExist: ident, $SecretKeyFileCanNotBeRead: ident, $SecretKeyFileHasInvalidContent: ident, $SecretKeyFileIsGloballyReadable: ident,
        $PublicKeyFileDoesNotExist: ident, $PublicKeyFileCanNotBeRead: ident, $PublicKeyFileHasInvalidContent: ident,
    ) => {
        if !$secret_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$SecretKeyFileDoesNotExist($context, $secret_path.clone()));
            }
        }
        else { // our secret key file exists
            if let Err(err) = $secret_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$SecretKeyFileCanNotBeRead($context, $secret_path.clone(), err));
                }
            }
            else { // our secret key file exists and is readable
                if $recipe.check_file_permissions && let Some(true) = $secret_path.is_world_readable() {
                    $warnings.push(Warning::$SecretKeyFileIsGloballyReadable($context, $secret_path.clone()));
                }
                if $recipe.check_key_file_contents {
                    match $static_kem_choice {
                        StaticKemChoice::McEliece460896Round2 => {
                            $warnings.push(Warning::CanNotCheckValidityOfStaticKemSecretKey($secret_path.clone(), $static_kem_choice))
                            // $errors.push(Error::UnimplementedFeature("checking the validity of McEliece460896Round2 secret key files".to_string()));
                        }
                        StaticKemChoice::McEliece460896Round4 => {
                            if let Err(_err) = SSk::load(&$secret_path) {
                                $errors.push(Error::$SecretKeyFileHasInvalidContent($context, $secret_path.clone(), $static_kem_choice));
                            }
                        }
                    }
                }
            }
        }
        if !$public_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$PublicKeyFileDoesNotExist($context, $public_path.clone()));
            }
        }
        else { // our public key file exists
            if let Err(err) = $public_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$PublicKeyFileCanNotBeRead($context, $public_path.clone(), err));
                }
            }
            else { // our public key file exists and is readable
                if $recipe.check_key_file_contents {
                    match $static_kem_choice {
                        StaticKemChoice::McEliece460896Round2 => {
                            $warnings.push(Warning::CanNotCheckValidityOfStaticKemPublicKey($public_path.clone(), $static_kem_choice))
                            // $errors.push(Error::UnimplementedFeature("checking the validity of McEliece460896Round2 public key files".to_string()));
                        }
                        StaticKemChoice::McEliece460896Round4 => {
                            if let Err(_err) = SPk::load(&$public_path) {
                                $errors.push(Error::$PublicKeyFileHasInvalidContent($context, $public_path.clone(), $static_kem_choice));
                            }
                        }
                    }
                }
            }
        }
    };
    ($secret_path: expr, $public_path: expr, $warnings: ident, $errors: ident, $recipe: ident, $static_kem_choice: expr,
        $SecretKeyFileDoesNotExist: ident, $SecretKeyFileCanNotBeRead: ident, $SecretKeyFileHasInvalidContent: ident, $SecretKeyFileIsGloballyReadable: ident,
        $PublicKeyFileDoesNotExist: ident, $PublicKeyFileCanNotBeRead: ident, $PublicKeyFileHasInvalidContent: ident,
    ) => {
        if !$secret_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$SecretKeyFileDoesNotExist($secret_path.clone()));
            }
        }
        else { // our secret key file exists
            if let Err(err) = $secret_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$SecretKeyFileCanNotBeRead($secret_path.clone(), err));
                }
            }
            else { // our secret key file exists and is readable
                if $recipe.check_file_permissions && let Some(true) = $secret_path.is_world_readable() {
                    $warnings.push(Warning::$SecretKeyFileIsGloballyReadable($secret_path.clone()));
                }
                if $recipe.check_key_file_contents {
                    match $static_kem_choice {
                        StaticKemChoice::McEliece460896Round2 => {
                            $warnings.push(Warning::CanNotCheckValidityOfStaticKemSecretKey($secret_path.clone(), $static_kem_choice))
                            // $errors.push(Error::UnimplementedFeature("checking the validity of McEliece460896Round2 secret key files".to_string()));
                        }
                        StaticKemChoice::McEliece460896Round4 => {
                            if let Err(_err) = SSk::load(&$secret_path) {
                                $errors.push(Error::$SecretKeyFileHasInvalidContent($secret_path.clone(), $static_kem_choice));
                            }
                        }
                    }
                }
            }
        }
        if !$public_path.is_file() {
            if $recipe.check_whether_files_exist {
                $errors.push(Error::$PublicKeyFileDoesNotExist($public_path.clone()));
            }
        }
        else { // our public key file exists
            if let Err(err) = $public_path.attempt_read() {
                if $recipe.check_file_permissions {
                    $errors.push(Error::$PublicKeyFileCanNotBeRead($public_path.clone(), err));
                }
            }
            else { // our public key file exists and is readable
                if $recipe.check_key_file_contents {
                    match $static_kem_choice {
                        StaticKemChoice::McEliece460896Round2 => {
                            $warnings.push(Warning::CanNotCheckValidityOfStaticKemPublicKey($public_path.clone(), $static_kem_choice))
                            // $errors.push(Error::UnimplementedFeature("checking the validity of McEliece460896Round2 public key files".to_string()));
                        }
                        StaticKemChoice::McEliece460896Round4 => {
                            if let Err(_err) = SPk::load(&$public_path) {
                                $errors.push(Error::$PublicKeyFileHasInvalidContent($public_path.clone(), $static_kem_choice));
                            }
                        }
                    }
                }
            }
        }
    };
}

impl super::RosenpassConfig {
    #[rustfmt::skip]
    pub fn validate(&self, recipe: ValidationRecipe) -> Result<Vec<Warning>, Vec<Issue>> {
        let mut errors: Vec<Error> = Vec::new();
        let mut warnings: Vec<Warning> = Vec::new();

        // ============================== [rosenpass] ==============================
        // check our key files
        #[cfg(not(feature = "experiment_crypto_agility"))]
        {
            validate_keypair!(
                self.our_keys.secret_key, self.our_keys.public_key,
                warnings, errors, recipe,
                self.algorithm.static_kem_choice,
                OurSecretKeyFileDoesNotExist,
                OurSecretKeyFileCanNotBeRead,
                OurSecretKeyFileHasInvalidContent,
                OurSecretKeyFileIsGloballyReadable,
                OurPublicKeyFileDoesNotExist,
                OurPublicKeyFileCanNotBeRead,
                OurPublicKeyFileHasInvalidContent,
            );
        }
        #[cfg(feature = "experiment_crypto_agility")]
        for keyconfig in self.our_keys.iter() {
            validate_keypair!(
                keyconfig.secret_key_file, keyconfig.public_key_file,
                warnings, errors, recipe,
                keyconfig.cipher,
                OurSecretKeyFileDoesNotExist,
                OurSecretKeyFileCanNotBeRead,
                OurSecretKeyFileHasInvalidContent,
                OurSecretKeyFileIsGloballyReadable,
                OurPublicKeyFileDoesNotExist,
                OurPublicKeyFileCanNotBeRead,
                OurPublicKeyFileHasInvalidContent,
            );
            if recipe.check_inconsistencies {
                // #[cfg(feature = "experiment_api")]
                // TODO: check for NeitherOurKeypairNorApiConnections
            }
        }
        // TODO: check algorithm choices
        // ============================== [[device]] ==============================
        for device in self.devices.iter() {
            // wg binary
            if let Some(wg_path) = device.path_to_wg_binary.as_ref() {
                if recipe.check_whether_files_exist && !wg_path.is_file() {
                    errors.push(Error::DevicesWireguardBinaryDoesNotExist(device.name.clone(), wg_path.clone()));
                }
                // TODO: check whether executable
                else if recipe.check_whether_external_binaries_behave && !wg_path.behaves_like_wg_binary() {
                    errors.push(Error::DevicesWireguardBinaryMisbehaves(device.name.clone(), wg_path.clone()));
                }
            }
            // managed by rosenpass
            match &device.wireguard_keypair_if_managed_by_rosenpass {
                None => {
                    if recipe.check_inconsistencies && device.managed_by == FlatDeviceManagedByChoice::Rosenpass {
                        errors.push(Error::DeviceIsManagedByRosenpassButMissesWireguardKeypair(device.name.clone()));
                    }
                },
                Some(wireguard_keypair) => {
                    // if the device is managed by rosenpass, these errors are thrown
                    if device.managed_by == FlatDeviceManagedByChoice::Rosenpass {
                        validate_keypair!(
                            wireguard_keypair.secret_key, wireguard_keypair.public_key,
                            warnings, errors, recipe,
                            self.algorithm.static_kem_choice,
                            device.name.clone(),
                            DeviceIsManagedByRosenpassButSecretKeyFileDoesNotExist,
                            DeviceIsManagedByRosenpassButSecretKeyFileCanNotBeRead,
                            DeviceIsManagedByRosenpassButSecretKeyFileHasInvalidContent,
                            DeviceIsManagedByRosenpassButSecretKeyFileIsGloballyReadable,
                            DeviceIsManagedByRosenpassButPublicKeyFileDoesNotExist,
                            DeviceIsManagedByRosenpassButPublicKeyFileCanNotBeRead,
                            DeviceIsManagedByRosenpassButPublicKeyFileHasInvalidContent,
                        );
                    }
                    // TODO: if the device is not managed by rosenpass, throw warnings similar to above errors
                }
            }
        }
        // ============================== [[peer]] ==============================
        for peer in self.peers.iter() {
            // TODO: name
            // TODO: if crypto-agile: algorithm
            // public key file
            if !peer.public_key_file.is_file() {
                if recipe.check_whether_files_exist {
                    errors.push(Error::PeerPublicKeyFileDoesNotExist(peer.name.clone(), peer.public_key_file.clone()));
                }
            }
            else { // public key file exists
                if let Err(err) = peer.public_key_file.attempt_read() {
                    if recipe.check_file_permissions {
                        errors.push(Error::PeerPublicKeyFileCanNotBeRead(peer.name.clone(), peer.public_key_file.clone(), err))
                    }
                }
                else { // public key file exists and is readable
                    // TODO: check whether file content is valid
                }
            }
            // TODO: endpoint
            // preshared key file
            if let Some(psk) = peer.preshared_key_file.as_ref() {
                if !psk.is_file() {
                    if recipe.check_whether_files_exist {
                        errors.push(Error::PeerPskFileDoesNotExist(peer.name.clone(), psk.clone()))
                    }
                }
                else { // psk file exists
                    if let Err(err) = psk.attempt_read() {
                        if recipe.check_file_permissions {
                            errors.push(Error::PeerPskFileCanNotBeRead(peer.name.clone(), psk.clone(), err));
                        }
                    }
                    else { // psk file exists and is readable
                        if recipe.check_file_permissions && let Some(true) = psk.is_world_readable() {
                            warnings.push(Warning::PresharedKeyFileIsGloballyReadable(psk.clone()));
                        }
                        // TODO: check whether file content is valid
                    }
                }
            }
            // osk domain separator
            if recipe.check_inconsistencies && let Err(err) = peer.osk_domain_separator.validate() {
                errors.push(Error::PeerHasInvalidOskDomainSeparator(peer.name.clone(), err));
            }
            // output to file
            if let Some(output_to_file) = peer.output_to_file.as_ref() {
                if output_to_file.enabled {
                    // note: do not check if file exists because that is not necessary
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
                    // else if recipe.check_file_permissions && !wg_binary.is_executable() {
                    //     errors.push(Error::PeersWireguardBinaryIsNotExecutable(peer.name, wg_binary.clone()));
                    // }
                    else if recipe.check_whether_external_binaries_behave && !wg_binary.behaves_like_wg_binary() {
                        errors.push(Error::PeersWireguardBinaryMisbehaves(peer.name.clone(), wg_binary.clone()));
                    }
                }
                // TODO: if managed by rosenpass
            }
            if peer.output_to_file.is_none() && peer.wireguard.is_none() {
                warnings.push(Warning::PeerHasNoKeyUsage(peer.name.clone()));
            }
        }
        // ============================== other ==============================
        // TODO: check wether this binary is ever used
        // if recipe.check_whether_external_binaries_behave && !PathBuf::from_str("wg").unwrap().behaves_like_wg_binary() {
        //     errors.push(Error::DefaultWireguardBinaryMisbehaves);
        // }
        // TODO: implement warnings

        // return
        if errors.is_empty() {
            Ok(warnings)
        }
        else {
            let mut issues: Vec::<Issue> = Vec::new();
            issues.extend(warnings.into_iter().map(|w|Issue::Warning(w)));
            issues.extend(errors.into_iter().map(|e|Issue::Error(e)));
            Err(issues)
        }
    }
}
