//! contains the implementation of [`RosenpassConfig::validate`]

use anyhow::{anyhow, ensure};

use super::{
    RosenpassConfig, ValidationRecipe,
    error::{Error, Issue, Warning},
    util::{AttemptRead, validate_keypair},
};

use crate::{
    config::DeviceWireguardOptions,
    protocol::basic_types::{SPk, SSk},
};
use crate::{config::WgDeviceCreateOptions, internal::util::file::LoadValue};

impl RosenpassConfig {
    /// convenience wrapper around [`RosenpassConfig::validate`] which adds this functionality:
    /// - print all validation results to console
    /// - does not return anything except a very short [`anyhow::Result`] with string that
    ///   `"validation failed"`
    pub fn validate_and_print(&self, recipe: ValidationRecipe) -> Result<(), anyhow::Error> {
        let result = self.validate(recipe);
        match &result {
            Ok(warnings) => {
                for warning in warnings.iter() {
                    println!("{}", warning);
                }
                Ok(())
            }
            Err(issues) => {
                for issue in issues.iter() {
                    println!("{}", issue);
                }
                Err(anyhow!("configuration file validation failed"))
            }
        }
    }
    /// check that the configuration is sound, ensuring for instance that the referenced files exist
    ///
    /// Refer to [`ValidationRecipe`] to see all checks that this function can run.
    ///
    /// # Examples
    ///
    /// ```ignore
    #[doc = include_str!("../../../tests/config_Rosenpass_validate.rs")]
    /// ```
    ///
    /// - TODO: warn if no wireguard devices defined and peers have defined WG devices (implicit definition)
    /// - TODO: warn if different OSK domain separators are set (not yet supported)
    /// - TODO: error if peer.wireguard.wireguard-options.allowed-ips is Some empty Vec<>
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
                WgDeviceCreateOptions::Create(DeviceWireguardOptions{wg_listen_port, wg_fwmark}) => {
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

// TODO: incorporate old validate checks
// pub fn validate(&self) -> anyhow::Result<()> {
//     if let Some(ref keypair) = self.our_keypair {
//         // check the public key file exists
//         ensure!(
//             keypair.public_key.is_file(),
//             "could not find public-key file {:?}: no such file. Consider running `rosenpass gen-keys` to generate a new keypair.",
//             keypair.public_key
//         );

//         // check the public-key file is a valid key
//         ensure!(
//             SPk::load(&keypair.public_key).is_ok(),
//             "could not load public-key file {:?}: invalid key",
//             keypair.public_key
//         );

//         // check the secret-key file exists
//         ensure!(
//             keypair.secret_key.is_file(),
//             "could not find secret-key file {:?}: no such file. Consider running `rosenpass gen-keys` to generate a new keypair.",
//             keypair.secret_key
//         );

//         // check the secret-key file is a valid key
//         ensure!(
//             SSk::load(&keypair.secret_key).is_ok(),
//             "could not load secret-key file {:?}: invalid key",
//             keypair.secret_key
//         );
//     }

//     for (i, peer) in self.peers.iter().enumerate() {
//         // check peer's public-key file exists
//         ensure!(
//             peer.public_key.is_file(),
//             "peer {i} public-key file {:?} does not exist",
//             peer.public_key
//         );

//         // check peer's public-key file is a valid key
//         ensure!(
//             SPk::load(&peer.public_key).is_ok(),
//             "peer {i} public-key file {:?} is invalid",
//             peer.public_key
//         );

//         // check endpoint is usable
//         if let Some(addr) = peer.endpoint.as_ref() {
//             ensure!(
//                 addr.to_socket_addrs().is_ok(),
//                 "peer {i} endpoint {} can not be parsed to a socket address",
//                 addr
//             );
//         }

//         // check if `key_out` or `device` and `peer` are defined
//         // TODO: this check is a bit messy, first introduced in b9e873e53475a7024a9608af7ceec6d53773153d
//         if peer.key_out.is_none() {
//             if let Some(wg) = &peer.wg {
//                 if wg.device.is_empty() || wg.peer.is_empty() {
//                     bail!("peer {i} has neither `key_out` nor valid wireguard config defined");
//                 }
//             } else {
//                 bail!("peer {i} has neither `key_out` nor valid wireguard config defined");
//             }
//         }

//         // check the WireGuard key binding configuration
//         if let Some(wg) = &peer.wg {
//             if peer.protocol_version == ProtocolVersion::V03 {
//                 ensure!(
//                     wg.our_wg_pubkey.is_some(),
//                     "peer {i} uses protocol version V03 and has a wireguard config, but no \
//                         `our_wg_pubkey` is set"
//                 );
//             }
//             if let Some(our_wg_pubkey) = &wg.our_wg_pubkey {
//                 ensure!(
//                     decode_wg_pubkey_b64(our_wg_pubkey).is_ok(),
//                     "peer {i} has an invalid `our_wg_pubkey` (expected a base64-encoded 32-byte key)"
//                 );
//             }
//         }

//         if let Err(e) = peer.osk_domain_separator.validate() {
//             bail!("Invalid OSK domain separation configuration for peer {i}: {e}");
//         }
//     }

//     Ok(())
// }

impl RosenpassConfig {
    /// Check that the configuration is useful given the feature set Rosenpass was compiled with
    /// and the configuration values.
    ///
    /// This was introduced when we introduced a unix-socket API feature allowing the server
    /// keypair to be supplied via the API; in this process we also made [Self::keypair] optional.
    /// With respect to this particular feature, this function ensures that [Self::keypair] is set
    /// when Rosenpass is compiles without the `experiment_api` flag. When `experiment_api` is
    /// used, the function ensures that [Self::keypair] is only `None`, if the Rosenpass API is
    /// enabled in the configuration.
    ///
    /// # Examples
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../../tests/config_Rosenpass_validate.rs")]
    #[doc = "```"]
    ///
    /// TODO: we might eventually want to find a more elegant way (maybe change the return type of
    /// [`RosenpassConfig::validate`]?)
    pub fn check_usefullness(&self) -> anyhow::Result<()> {
        // without the `experiment_api` feature, usufulness is constrained by [`RosenpassConfig`]
        // type definition
        #[cfg(not(feature = "experiment_api"))]
        return Ok(());

        #[cfg(feature = "experiment_api")]
        return if self.api.has_api_sources() {
            // usefulness is given because the user can supply key pairs via the API
            Ok(())
        } else {
            // check that our keypair is set
            use crate::config::PublicKeySource;
            let secret = (self.our_keypair.secret_key_source.is_defined(), "secret");
            let public = (self.our_keypair.public_key_source.is_defined(), "public");
            for (is_defined, key_name) in [secret, public] {
                ensure!(
                    is_defined,
                    "{}{}",
                    "Specify a server keypair or some API connections to configure the keypair with.",
                    "Without a keypair, rosenpass can not operate."
                );
            }
            // both keys supplied, so the usefulness check passes
            Ok(())
        };
    }
}
