//! contains the implementation of [`RosenpassConfig::validate`]

use super::{
    RosenpassConfig, ValidationRecipe,
    error::{Error, Issue, Warning},
    util::{AttemptRead, validate_keypair},
};

use crate::protocol::basic_types::{SPk, SSk};
use crate::{config::WgDeviceCreateOptions, internal::util::file::LoadValue};

impl RosenpassConfig {
    /// - TODO: write documentation
    /// - TODO: warn if no wireguard devices defined and peers have defined WG devices (implicit definition)
    /// - TODO: warn if different OSK domain separators are set (not yet supported)
    #[rustfmt::skip]
    pub fn validate(&self, recipe: ValidationRecipe) -> Result<Vec<Warning>, Vec<Issue>> {
        let mut errors: Vec<Error> = Vec::new();
        let mut warnings: Vec<Warning> = Vec::new();

        // ============================== [rosenpass] ==============================
        // check our key files
        {
            // TODO
            // validate_keypair!(
            //     self.our_keypair.secret_key_source, self.our_keypair.public_key_source,
            //     warnings, errors, recipe,
            //     OurSecretKeyFileDoesNotExist,
            //     OurSecretKeyFileCanNotBeRead,
            //     OurSecretKeyFileHasInvalidContent,
            //     OurSecretKeyFileIsGloballyReadable,
            //     OurPublicKeyFileDoesNotExist,
            //     OurPublicKeyFileCanNotBeRead,
            //     OurPublicKeyFileHasInvalidContent,
            // );
        }
        // TODO: check algorithm choices
        // ============================== [[device]] ==============================
        for device in self.wireguard_devices.iter() {
            // managed by rosenpass
            match &device.created_by {
                WgDeviceCreateOptions::DoNotCreate => {}
                // TODO:
                // {
                //     if recipe.check_inconsistencies && device.managed_by == FlatDeviceManagedByChoice::Rosenpass {
                //         errors.push(Error::DeviceIsManagedByRosenpassButMissesWireguardKeypair(device.name.clone()));
                //     }
                // },
                WgDeviceCreateOptions::Create{wg_listen_port, wg_fwmark} => {
                    // TODO: check wg_listen_port

                    // TODO: check wg_fwmark

                    // TODO:
                    // // if the device is managed by rosenpass, these errors are thrown
                    // if device.managed_by == FlatDeviceManagedByChoice::Rosenpass {
                    //     validate_keypair!(
                    //         wireguard_keypair.secret_key, wireguard_keypair.public_key,
                    //         warnings, errors, recipe,
                    //         device.name.clone(),
                    //         DeviceIsManagedByRosenpassButSecretKeyFileDoesNotExist,
                    //         DeviceIsManagedByRosenpassButSecretKeyFileCanNotBeRead,
                    //         DeviceIsManagedByRosenpassButSecretKeyFileHasInvalidContent,
                    //         DeviceIsManagedByRosenpassButSecretKeyFileIsGloballyReadable,
                    //         DeviceIsManagedByRosenpassButPublicKeyFileDoesNotExist,
                    //         DeviceIsManagedByRosenpassButPublicKeyFileCanNotBeRead,
                    //         DeviceIsManagedByRosenpassButPublicKeyFileHasInvalidContent,
                    //     );
                    // }
                    // // TODO: if the device is not managed by rosenpass, throw warnings similar to above errors
                }
            }
        }
        // ============================== [[peer]] ==============================
        for peer in self.peers.iter() {
            // // TODO: name
            // // TODO: if crypto-agile: algorithm
            // // public key file
            // if !peer.public_key_file.is_file() {
            //     if recipe.check_whether_files_exist {
            //         errors.push(Error::PeerPublicKeyFileDoesNotExist(peer.name.clone(), peer.public_key_file.clone()));
            //     }
            // }
            // else { // public key file exists
            //     if let Err(err) = peer.public_key_file.attempt_read() {
            //         if recipe.check_file_permissions {
            //             errors.push(Error::PeerPublicKeyFileCanNotBeRead(peer.name.clone(), peer.public_key_file.clone(), err))
            //         }
            //     }
            //     else { // public key file exists and is readable
            //         // TODO: check whether file content is valid
            //     }
            // }
            // // TODO: endpoint
            // // preshared key file
            // if let Some(psk) = peer.preshared_key.as_ref() {
            //     if !psk.is_file() {
            //         if recipe.check_whether_files_exist {
            //             errors.push(Error::PeerPskFileDoesNotExist(peer.name.clone(), psk.clone()))
            //         }
            //     }
            //     else { // psk file exists
            //         if let Err(err) = psk.attempt_read() {
            //             if recipe.check_file_permissions {
            //                 errors.push(Error::PeerPskFileCanNotBeRead(peer.name.clone(), psk.clone(), err));
            //             }
            //         }
            //         else { // psk file exists and is readable
            //             if recipe.check_file_permissions && let Some(true) = psk.is_world_readable() {
            //                 warnings.push(Warning::PresharedKeyFileIsGloballyReadable(psk.clone()));
            //             }
            //             // TODO: check whether file content is valid
            //         }
            //     }
            // }
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
                if recipe.check_inconsistencies && self.wireguard_devices.iter().find(|d| d.name == wireguard.device_name).is_none() {
                    if wireguard.enabled {
                        errors.push(Error::EnabledPeerWireguardUsesUndefinedDevice(peer.name.clone(), wireguard.device_name.clone()));
                    }
                    else {
                        warnings.push(Warning::DisabledPeerUsesUndefinedDevice(peer.name.clone(), wireguard.device_name.clone()));
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
