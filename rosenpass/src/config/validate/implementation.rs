//! contains the implementation of [`RosenpassConfig::validate`]

use std::net::ToSocketAddrs;

use super::{
    RosenpassConfig, ValidationRecipe,
    error::{Error, Issue, Warning},
    util::{AttemptRead, check_key_file},
};
use crate::{
    config::{KeyFromDiskOrB64EncodedStringInner, PublicKeySource, decode_wg_pubkey_b64},
    internal::util::file::LoadValueB64,
    protocol::{
        ProtocolVersion,
        basic_types::{SPk, SSk, SymKey},
    },
};
use crate::{
    config::{WgDeviceCreateOptions, parse_from_toml::util::GuaranteedUnwrap},
    internal::util::file::LoadValue,
};
use anyhow::{anyhow, ensure};

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
    // #[rustfmt::skip]
    pub fn validate(&self, recipe: ValidationRecipe) -> Result<Vec<Warning>, Vec<Issue>> {
        // let mut errors: Vec<Error> = Vec::new();
        // let mut warnings: Vec<Warning> = Vec::new();
        let mut issues: Vec<Issue> = Vec::new();

        // ============================== [rosenpass] ==============================
        // check our key files
        {
            check_key_file(
                &mut issues,
                recipe,
                self.our_keypair.secret_key_source.get_key_path().as_path(),
                |p| Error::OurSecretKeyFileDoesNotExist(p).into(),
                |p, e| Error::OurSecretKeyFileCanNotBeRead(p, e).into(),
                |p| Some(Warning::OurSecretKeyFileIsGloballyReadable(p).into()),
                |p| {
                    SSk::load(&p)
                        .map_err(|err| Error::OurSecretKeyFileHasInvalidContent(p, err).into())
                        .err()
                },
            );
            check_key_file(
                &mut issues,
                recipe,
                self.our_keypair.public_key_source.get_key_path().as_path(),
                |p| Error::OurPublicKeyFileDoesNotExist(p).into(),
                |p, err| Error::OurPublicKeyFileCanNotBeRead(p, err).into(),
                |p| None,
                |p| {
                    SPk::load(&p)
                        .map_err(|err| Error::OurPublicKeyFileHasInvalidContent(p, err).into())
                        .err()
                },
            );
        }
        // ============================== [[device]] ==============================
        // duplicate device names
        // TODO: this code is not DRY – peer has some similar code
        // TODO: warn about devices which are not used by any peer config
        if recipe.check_inconsistencies {
            use itertools::Itertools;
            let duplicate_peer_names = self
                .wireguard_devices
                .iter()
                .filter(|d| d.enabled)
                .map(|d| d.name.clone())
                .duplicates()
                .collect::<Vec<String>>();
            for duplicate in duplicate_peer_names {
                issues.push(Error::DuplicateDeviceName(duplicate).into());
            }
        }
        for device in self.wireguard_devices.iter() {
            // name
            {
                // TODO: this code is not DRY – peer has some similar code
                let device_name_len = device.name.chars().count();
                const DEVICE_MAX_NAME_LEN: usize = 30;
                if device_name_len > DEVICE_MAX_NAME_LEN {
                    issues.push(
                        Warning::DeviceHasVeryLongName(
                            device.name.clone(),
                            device_name_len,
                            DEVICE_MAX_NAME_LEN,
                        )
                        .into(),
                    );
                }
            }
            // enabled
            if !device.enabled {
                if recipe.warn_about_disabled_entries {
                    issues.push(Warning::DeviceIsDisabled(device.name.clone()).into());
                }
            } else {
                // created_by
                match &device.created_by {
                    WgDeviceCreateOptions::DoNotCreate => {}
                    WgDeviceCreateOptions::Create(options) => {
                        // TODO: check wg_listen_port
                        // TODO: check wg_fwmark
                        // TODO: set_ip_addr,
                        // TODO: set_listen_port,
                        // TODO: set_secret_key,
                    }
                }
            }
        }
        // ============================== [[peer]] ==============================
        // duplicate peer names
        if recipe.check_inconsistencies {
            use itertools::Itertools;
            let duplicate_peer_names = self
                .peers
                .iter()
                .filter(|p| p.enabled)
                .map(|p| p.name.clone())
                .duplicates()
                .collect::<Vec<String>>();
            for duplicate in duplicate_peer_names {
                issues.push(Error::DuplicatePeerName(duplicate).into());
            }
        }
        for peer in self.peers.iter() {
            // name
            {
                let peer_name_len = peer.name.chars().count();
                const PEER_MAX_NAME_LEN: usize = 30;
                if peer_name_len > PEER_MAX_NAME_LEN {
                    issues.push(
                        Warning::PeerHasVeryLongName(
                            peer.name.clone(),
                            peer_name_len,
                            PEER_MAX_NAME_LEN,
                        )
                        .into(),
                    );
                }
            }
            // enabled (stop checks after this if not enabled)
            if !peer.enabled {
                if recipe.warn_about_disabled_entries {
                    issues.push(Warning::PeerIsDisabled(peer.name.clone()).into());
                }
                continue;
            }
            // their public key
            check_key_file(
                &mut issues,
                recipe,
                peer.their_public_key.get_key_path().as_path(),
                |p| Error::PeerPublicKeyFileDoesNotExist(peer.name.clone(), p).into(),
                |p, err| Error::PeerPublicKeyFileCanNotBeRead(peer.name.clone(), p, err).into(),
                |_p| None,
                |p| {
                    SPk::load(&p)
                        .map_err(|err| {
                            Error::PeerPublicKeyFileHasInvalidContent(peer.name.clone(), p, err)
                                .into()
                        })
                        .err()
                },
            );

            // resolve endpoint
            if recipe.look_up_hostnames
                && let Some(endpoint) = peer.endpoint.as_ref()
            {
                if let Err(err) = endpoint.to_socket_addrs() {
                    issues.push(
                        Error::InvalidPeerEndpoint(peer.name.clone(), endpoint.clone(), err).into(),
                    );
                }
            }

            // PSK
            if let Some(psk) = peer.preshared_key.as_ref() {
                check_key_file(
                    &mut issues,
                    recipe,
                    psk.get_key_file_path().as_path(),
                    |p| Error::PeerPskFileDoesNotExist(peer.name.clone(), p).into(),
                    |p, err| Error::PeerPskFileCanNotBeRead(peer.name.clone(), p, err).into(),
                    |p| Some(Warning::PeerPskFileIsGloballyReadable(peer.name.clone(), p).into()),
                    |p| {
                        const MAX_PSK_SIZE: usize = 1000; // TODO: this is not very DRY
                        SymKey::load_b64::<MAX_PSK_SIZE, _>(p.clone())
                            .map_err(|err| {
                                Error::PeerPskFileHasInvalidContent(peer.name.clone(), p, err)
                                    .into()
                            })
                            .err()
                    },
                );
            }

            // OSK domain separator
            if recipe.check_inconsistencies
                && let Err(err) = peer.osk_domain_separator.validate()
            {
                issues.push(Error::PeerHasInvalidOskDomainSeparator(peer.name.clone(), err).into());
            }
            // TODO: check that WG and outfile OSK domain separator do not differ (because this is not yet supported)

            // output to file
            if let Some(output_to_file) = peer.output_to_file.as_ref() {
                if !output_to_file.enabled {
                    if recipe.warn_about_disabled_entries {
                        issues.push(Warning::PeerOutputToFileIsDisabled(peer.name.clone()).into());
                    }
                } else {
                    // output_file_path
                    // note: do not check if file exists because that is not necessary
                    let p = output_to_file.output_file_path.clone();
                    if recipe.check_file_permissions
                        && let Err(err) = p.attempt_write()
                    {
                        issues.push(
                            Error::PeerOutputToFileNotWritable(peer.name.clone(), p, err).into(),
                        );
                    }
                    // osk_domain_separator
                    if recipe.check_inconsistencies
                        && let Err(err) = output_to_file.osk_domain_separator.validate()
                    {
                        issues.push(
                            Error::PeerHasInvalidOskDomainSeparatorInOutfile(
                                peer.name.clone(),
                                err,
                            )
                            .into(),
                        );
                    }
                }
            }

            // wireguard
            if let Some(wireguard) = peer.wireguard.as_ref() {
                // enabled
                if !wireguard.enabled {
                    if recipe.warn_about_disabled_entries {
                        issues.push(Warning::PeerWireGuardIsDisabled(peer.name.clone()).into());
                    }
                } else {
                    // device_name
                    if recipe.check_inconsistencies
                        && self
                            .wireguard_devices
                            .iter()
                            .any(|d| d.name == wireguard.device_name)
                    {
                        issues.push(
                            Error::EnabledPeerWireguardUsesUndefinedDevice(
                                peer.name.clone(),
                                wireguard.device_name.clone(),
                            )
                            .into(),
                        );
                    }
                    // our_wireguard_keypair
                    if let Some(wgsk) = wireguard
                        .our_wireguard_keypair
                        .as_ref()
                        .map(|pair| pair.get_secret_key())
                        .flatten()
                    {
                        check_key_file(
                            &mut issues,
                            recipe,
                            wgsk.get_key_path().as_path(),
                            |p| {
                                Error::PeerWireguardOurSecretKeyFileDoesNotExist(
                                    peer.name.clone(),
                                    p,
                                )
                                .into()
                            },
                            |p, err| {
                                Error::PeerWireguardOurSecretKeyFileCanNotBeRead(
                                    peer.name.clone(),
                                    p,
                                    err,
                                )
                                .into()
                            },
                            |p| {
                                Some(
                                    Warning::PeerWireguardOurSecretKeyFileIsGloballyReadable(
                                        peer.name.clone(),
                                        p,
                                    )
                                    .into(),
                                )
                            },
                            |p| {
                                None
                                // todo!("check key file contents of wgsk file");
                                // Error::PeerWireguardOurSecretKeyFileHasInvalidContent(
                                //     peer.name.clone(),
                                //     p,
                                //     err,
                                // )
                                // .into()
                            },
                        );
                    }
                    if let Some(wgpk) = wireguard
                        .our_wireguard_keypair
                        .as_ref()
                        .map(|pair| pair.get_public_key())
                    {
                        match &wgpk.inner {
                            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(b64) => {
                                if recipe.check_key_file_contents
                                    && let Err(err) = decode_wg_pubkey_b64(b64)
                                {
                                    issues.push(
                                        Error::PeerWireguardOurPublicKeyInlineHasInvalidContent(
                                            peer.name.clone(),
                                            err,
                                        )
                                        .into(),
                                    );
                                }
                            }
                            _ => {
                                check_key_file(
                                    &mut issues,
                                    recipe,
                                    wgpk.get_key_path()
                                        .expect(
                                            "TODO: unreachable but should be caught be type system",
                                        )
                                        .as_path(),
                                    |p| {
                                        Error::PeerWireguardOurPublicKeyFileDoesNotExist(
                                            peer.name.clone(),
                                            p,
                                        )
                                        .into()
                                    },
                                    |p, err| {
                                        Error::PeerWireguardOurPublicKeyFileCanNotBeRead(
                                            peer.name.clone(),
                                            p,
                                            err,
                                        )
                                        .into()
                                    },
                                    |p| None,
                                    |p| {
                                        None
                                        // todo!("check key file contents of wgpk file");
                                        // Error::PeerWireguardOurPublicKeyFileHasInvalidContent(
                                        //     peer.name.clone(),
                                        //     p,
                                        //     err,
                                        // ).into()
                                    },
                                );
                            }
                        }
                    }

                    // check the WireGuard key binding configuration
                    // TODO: allow to set per-peer protocol version
                    // https://github.com/rosenpass/rosenpass/issues/1196
                    if recipe.check_inconsistencies {
                        let protocol_version = self
                            .supported_protocol_versions
                            .first()
                            .copied()
                            .unwrap_or_default();
                        match protocol_version {
                            ProtocolVersion::V02 => (),
                            ProtocolVersion::V03 => {
                                if wireguard
                                    .our_wireguard_keypair
                                    .as_ref()
                                    .map(|pair| pair.get_public_key())
                                    .is_none()
                                {
                                    issues.push(
                                        Error::PeerNeedsToBindToOurWgPubkey(
                                            peer.name.clone(),
                                            protocol_version,
                                        )
                                        .into(),
                                    );
                                }
                            }
                        }
                    }

                    // TODO: their_wireguard_public_key

                    // TODO: validate base64-encoded WireGuard public key

                    // TODO: wireguard_options
                    // TODO: exchange_command
                    // TODO: osk_domain_separator
                }
            }
            if peer.output_to_file.is_none() && peer.wireguard.is_none() {
                issues.push(Warning::PeerHasNoKeyUsage(peer.name.clone()).into());
            }
        }
        // ============================== other ==============================
        // TODO: check wether this binary is ever used
        // if recipe.check_whether_external_binaries_behave && !PathBuf::from_str("wg").unwrap().behaves_like_wg_binary() {
        //     errors.push(Error::DefaultWireguardBinaryMisbehaves);
        // }
        // TODO: implement more warnings

        // return
        if issues.iter().any(|i| i.as_error().is_some()) {
            Err(issues)
        } else {
            Ok(issues
                .into_iter()
                .map(|i| i.to_warning().guaranteed_unwrap())
                .collect::<Vec<Warning>>())
        }
    }
}

impl RosenpassConfig {
    /// Check that the configuration is useful given the feature set Rosenpass was compiled with
    /// and the configuration values.
    ///
    /// This was introduced when we introduced a unix-socket API feature allowing the server
    /// keypair to be supplied via the API; in this process we also made [Self::our_keypair] optional.
    /// With respect to this particular feature, this function ensures that [Self::our_keypair] is set
    /// when Rosenpass is compiles without the `experiment_api` flag. When `experiment_api` is
    /// used, the function ensures that [Self::our_keypair] is only `None`, if the Rosenpass API is
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
