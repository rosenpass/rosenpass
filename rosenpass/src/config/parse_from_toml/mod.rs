use crate::oldconfig::util::ResolvePathWithTilde;
use log::LevelFilter;
use std::str::FromStr;
use toml_edit::Table;
#[cfg(feature = "experiment_crypto_agility")]
use util::get_as_asymmetric_cipher_type;
use util::{
    get_as_array, get_as_crypto_algorithm_choice, get_as_flat_device_managed_by_choice,
    get_as_opt_log_level, get_as_opt_path_buf, get_as_opt_vec_string, get_as_path_buf,
    get_as_protocol_version, get_as_socket_addr, get_as_string, process_result,
};

#[cfg(not(feature = "experiment_crypto_agility"))]
use crate::config::parse_from_toml::util::get_as_inline_table;
use crate::{
    config::parse_from_toml::util::{get_as_opt_inline_table, get_as_opt_string},
    oldconfig::{Keypair, RosenpassPeerOskDomainSeparator},
};

use super::types::*;
use errors::{ParseError, ParseIssue, ParseWarning};
pub mod errors;
pub mod util;

impl RosenpassConfig {
    /// if successful, returns a [RosenpassConfig] and a list of warnings
    /// if failing, returns a list of errors and warnings
    pub fn parse_from_toml(
        document: toml_edit::Document<String>,
        working_directory: &std::path::PathBuf,
    ) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
        let mut warnings: Vec<ParseWarning> = Vec::new();
        let mut errors: Vec<ParseError> = Vec::new();
        let raw = document.raw();

        let get_array_of_tables = |name: &str| -> Result<&toml_edit::ArrayOfTables, ParseError> {
            let item = document.get(name).ok_or_else(|| {
                ParseError::new(
                    raw,
                    document.span(),
                    format!("missing array of tables \"[[{name}]]\""),
                )
            })?;
            let return_value = item.as_array_of_tables().ok_or_else(|| {
                ParseError::new(
                    raw,
                    item.span(),
                    format!(
                        "item \"{name}\" {}",
                        "has wrong data type, must be array of tables"
                    ),
                )
            })?;
            Ok(return_value)
        };

        // ============================== [rosenpass] ==============================
        let mut our_listen_adresses = Vec::new();
        let mut log_level: Option<LevelFilter> = None;
        let mut logging_output_file = None;
        #[cfg(feature = "experiment_crypto_agility")]
        let mut our_keys: Vec<OurKeyConfig> = Vec::new();
        #[cfg(not(feature = "experiment_crypto_agility"))]
        let mut our_keys: Option<Keypair> = None;
        let mut our_algorithm: Option<CryptoAlgorithmsChoice> = None;
        {
            let mut process_rosenpass_table = |table: &Table| {
                // our_listen_addresses
                if let Some(listen_addresses) =
                    process_result!(errors, get_as_array(raw, table, table.span(), "listen"))
                {
                    if listen_addresses.is_empty() {
                        errors.push(ParseError::new(
                            raw,
                            listen_addresses.span(),
                            format!(
                                "listen addresses list is empty, require at least one list address"
                            ),
                        ));
                    }
                    for listen_address in listen_addresses.iter() {
                        let value = process_result!(
                            errors,
                            listen_address.as_str().ok_or_else(|| {
                                ParseError::new(
                                    raw,
                                    listen_address.span(),
                                    format!("item in list has wrong data type: should be string"),
                                )
                            })
                        );
                        if let Some(value) = value {
                            let addr = process_result!(
                                errors,
                                std::net::SocketAddr::from_str(value).map_err(|err| {
                                    ParseError::new(raw, listen_address.span(), err.to_string())
                                })
                            );
                            if let Some(addr) = addr {
                                our_listen_adresses.push(addr);
                            }
                        }
                    }
                }
                // log_level
                log_level = process_result!(
                    errors,
                    get_as_opt_log_level(raw, table, table.span(), "logging-level")
                )
                .flatten();
                // logging_output_file
                logging_output_file = process_result!(
                    errors,
                    get_as_opt_path_buf(raw, table, table.span(), "logging-output-file")
                )
                .flatten()
                .map(|p| p.resolve_relative_with_tilde(working_directory));

                // our_keys
                #[cfg(not(feature = "experiment_crypto_agility"))]
                if let Some(inline_table) = process_result!(
                    errors,
                    get_as_inline_table(raw, table, table.span(), "keys")
                ) {
                    let mut inline_errors = Vec::new();
                    let secret = process_result!(
                        inline_errors,
                        get_as_path_buf(raw, inline_table, inline_table.span(), "secret-key-file")
                    )
                    .map(|p| p.resolve_relative_with_tilde(working_directory));
                    let public = process_result!(
                        inline_errors,
                        get_as_path_buf(raw, inline_table, inline_table.span(), "public-key-file")
                    )
                    .map(|p| p.resolve_relative_with_tilde(working_directory));
                    if !inline_errors.is_empty() {
                        errors.append(&mut inline_errors);
                    } else {
                        our_keys = Some(Keypair {
                            secret_key: secret.expect("unreachable"),
                            public_key: public.expect("unreachable"),
                        });
                    }
                }
                #[cfg(feature = "experiment_crypto_agility")]
                if let Some(keys_list) =
                    process_result!(errors, get_as_array(raw, table, table.span(), "keys"))
                {
                    if keys_list.is_empty() {
                        errors.push(ParseError::new(
                            raw,
                            keys_list.span(),
                            format!("keys list is empty, require at least one keypair"),
                        ));
                    }
                    for key_item in keys_list.iter() {
                        let key_item =
                            process_result!(errors,key_item.as_inline_table().ok_or_else(|| {
                                ParseError::new(
                                    raw,
                                    key_item.span(),
                                    format!(
                                        "expected an array of inline tables but array contains {}",
                                        key_item.type_name()
                                    ),
                                )
                            }));
                        let mut key_item_errors = if let Some(key_item) = key_item {
                            let mut errors: Vec<ParseError> = Vec::new();
                            let cipher = process_result!(
                                errors,
                                get_as_asymmetric_cipher_type(
                                    raw,
                                    key_item,
                                    key_item.span(),
                                    "cipher"
                                )
                            );
                            let secret_key_file = process_result!(
                                errors,
                                get_as_path_buf(raw, key_item, key_item.span(), "secret-key-file")
                            )
                            .map(|p| p.resolve_relative_with_tilde(working_directory));
                            let public_key_file = process_result!(
                                errors,
                                get_as_path_buf(raw, key_item, key_item.span(), "public-key-file")
                            )
                            .map(|p| p.resolve_relative_with_tilde(working_directory));
                            if !errors.is_empty() {
                                errors
                            } else {
                                our_keys.push(OurKeyConfig {
                                    cipher: cipher.expect("unreachable"),
                                    secret_key_file: secret_key_file.expect("unreachable"),
                                    public_key_file: public_key_file.expect("unreachable"),
                                });
                                vec![]
                            }
                        } else {
                            vec![]
                        };
                        errors.append(&mut key_item_errors);
                    }
                }

                // our_algorithm
                #[cfg(not(feature = "experiment_crypto_agility"))]
                {
                    eprintln!(
                        "algorithm type: {}",
                        table.get("algorithm").unwrap().type_name()
                    );
                    our_algorithm = process_result!(
                        errors,
                        get_as_crypto_algorithm_choice(raw, table, table.span(), "algorithm")
                    );
                }
            };
            if let Some(rosenpass_table) = document.get("rosenpass").map(|v| v.as_table()).flatten()
            {
                process_rosenpass_table(rosenpass_table);
            } else {
                process_rosenpass_table(document.as_table());
            }
        }
        // ============================== [[device]] ==============================
        let mut devices: Vec<DeviceConfig> = Vec::new();
        if let Some(device_tables) = process_result!(errors, get_array_of_tables("device")) {
            for table in device_tables {
                // TODO: remove unwrap()s
                let mut device_errors = {
                    let mut errors = Vec::new();
                    let name =
                        process_result!(errors, get_as_string(raw, table, table.span(), "name"));
                    let managed_by = process_result!(
                        errors,
                        get_as_flat_device_managed_by_choice(
                            raw,
                            table,
                            table.span(),
                            "managed-by",
                        )
                    );
                    // .map(|managed_by| match managed_by {
                    //     FlatDeviceManagedByChoice::Wireguard => Some(DeviceManagedByChoice::Wireguard),
                    //     FlatDeviceManagedByChoice::Rosenpass => {
                    //         todo!("read additional data")
                    //     }
                    // })
                    // .flatten();
                    let wireguard_keypair_if_managed_by_rosenpass: Option<Keypair> = table
                        .get("if-managed-by-rosenpass")
                        .map(|inline_table| match inline_table.as_inline_table() {
                            None => {
                                errors.push(ParseError::new(
                                    raw,
                                    inline_table.span(),
                                    format!(
                                        "{}, {}",
                                        "item \"if-managed-by-rosenpass\" has wrong data type",
                                        "must be inline table"
                                    ),
                                ));
                                None
                            }
                            Some(inline_table) => {
                                let mut inline_errors = Vec::new();
                                let secret_key = process_result!(
                                    inline_errors,
                                    get_as_path_buf(
                                        raw,
                                        inline_table,
                                        inline_table.span(),
                                        "wireguard-secret-key-file",
                                    )
                                )
                                .map(|p| p.resolve_relative_with_tilde(working_directory));
                                let public_key = process_result!(
                                    inline_errors,
                                    get_as_path_buf(
                                        raw,
                                        inline_table,
                                        inline_table.span(),
                                        "wireguard-public-key-file"
                                    )
                                )
                                .map(|p| p.resolve_relative_with_tilde(working_directory));
                                if !inline_errors.is_empty() {
                                    errors.append(&mut inline_errors);
                                    None
                                } else {
                                    Some(Keypair {
                                        secret_key: secret_key.expect("unreachable"),
                                        public_key: public_key.expect("unreachable"),
                                    })
                                }
                            }
                        })
                        .flatten();

                    let path_to_wg_binary = process_result!(
                        errors,
                        get_as_opt_path_buf(raw, table, table.span(), "wg-binary-path")
                    )
                    .flatten()
                    .map(|p| p.resolve_relative_with_tilde(working_directory));
                    if errors.is_empty() {
                        devices.push(DeviceConfig {
                            name: name.expect("unreachable"),
                            managed_by: managed_by.expect("unreachable"),
                            wireguard_keypair_if_managed_by_rosenpass:
                                wireguard_keypair_if_managed_by_rosenpass,
                            path_to_wg_binary: path_to_wg_binary,
                        });
                    }
                    errors
                };
                errors.append(&mut device_errors);
            }
        }
        // ============================== [[peer]] ==============================
        let mut peers = Vec::new();
        if let Some(peer_tables) = process_result!(errors, get_array_of_tables("peer")) {
            for table in peer_tables {
                let mut peer_errors = {
                    let mut errors = Vec::new();
                    let name =
                        process_result!(errors, get_as_string(raw, table, table.span(), "name"));
                    #[cfg(feature = "experiment_crypto_agility")]
                    let algorithm = process_result!(
                        errors,
                        get_as_crypto_algorithm_choice(raw, table, table.span(), "algorithm")
                    );
                    let public_key_file = process_result!(
                        errors,
                        get_as_path_buf(raw, table, table.span(), "public-key-file")
                    )
                    .map(|p| p.resolve_relative_with_tilde(working_directory));
                    let protocol_version = process_result!(
                        errors,
                        get_as_protocol_version(raw, table, table.span(), "protocol-version")
                    );
                    let endpoint = process_result!(
                        errors,
                        get_as_socket_addr(raw, table, table.span(), "endpoint")
                    );
                    let preshared_key_file = process_result!(
                        errors,
                        get_as_opt_path_buf(raw, table, table.span(), "preshared-key-file")
                    )
                    .flatten()
                    .map(|p| p.resolve_relative_with_tilde(working_directory));
                    let osk_domain_separator = process_result!(
                        errors,
                        get_as_opt_inline_table(raw, table, table.span(), "osk-domain-separator")
                    )
                    .flatten()
                    .map(|inline_table| {
                        let mut inline_errors = Vec::new();
                        let organization = process_result!(
                            inline_errors,
                            get_as_opt_string(
                                raw,
                                inline_table,
                                inline_table.span(),
                                "organization"
                            )
                        );
                        let osk_labels = process_result!(
                            inline_errors,
                            get_as_opt_vec_string(raw, inline_table, inline_table.span(), "labels")
                        );
                        if !inline_errors.is_empty() {
                            errors.append(&mut inline_errors);
                            None
                        } else {
                            Some(RosenpassPeerOskDomainSeparator {
                                osk_organization: organization.expect("unrechable"),
                                osk_label: osk_labels.expect("unreachable"),
                            })
                        }
                    })
                    .flatten()
                    .unwrap_or(RosenpassPeerOskDomainSeparator {
                        osk_organization: None,
                        osk_label: None,
                    });

                    if errors.is_empty() {
                        peers.push(PeerConfig {
                            name: name.expect("unreachable"),
                            #[cfg(feature = "experiment_crypto_agility")]
                            algorithm: algorithm.expect("unreachable"),
                            public_key_file: public_key_file.expect("unreachable"),
                            protocol_version: protocol_version.expect("unreachable"),
                            endpoint: endpoint.expect("unreachable"),
                            preshared_key_file: preshared_key_file,
                            osk_domain_separator: osk_domain_separator,
                            output_to_file: None, //todo!(),
                            wireguard: None,      //todo!(),
                        })
                    }
                    errors
                };
                errors.append(&mut peer_errors);
            }
        }
        // ============================== return ==============================
        if !errors.is_empty() {
            let mut issues: Vec<ParseIssue> = Vec::new();
            issues.extend(warnings.into_iter().map(|w| ParseIssue::Warning(w)));
            issues.extend(errors.into_iter().map(|e| ParseIssue::Error(e)));
            Err(issues)
        } else {
            Ok((
                RosenpassConfig {
                    our_listen_addresses: our_listen_adresses,
                    #[cfg(not(feature = "experiment_crypto_agility"))]
                    our_keys: our_keys.expect("unreachable"),
                    #[cfg(feature = "experiment_crypto_agility")]
                    our_keys: our_keys,
                    #[cfg(not(feature = "experiment_crypto_agility"))]
                    algorithm: our_algorithm.expect("unreachable"),
                    log_level: log_level.unwrap_or(LevelFilter::Info),
                    logging_output_file: logging_output_file,
                    #[cfg(feature = "experiment_api")]
                    api: todo!(),
                    devices: devices,
                    peers: peers,
                },
                warnings,
            ))
        }
    }
}
