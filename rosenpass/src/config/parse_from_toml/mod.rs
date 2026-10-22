use crate::oldconfig::Verbosity;
use crate::oldconfig::util::ResolvePathWithTilde;
use log::LevelFilter;
use std::path::Path;
use std::str::FromStr;
use toml_edit::Table;
use util::{
    get_as_array, get_as_opt_log_level, get_as_opt_path_buf, get_as_opt_vec_string,
    get_as_path_buf, get_as_protocol_version, get_as_socket_addr, get_as_string, process_result,
};

use crate::config::parse_from_toml::util::{
    get_as_bool, get_as_inline_table, get_as_opt_bool, get_as_opt_osk_domain_separator, get_as_opt_psk_source, get_as_opt_socket_addr, get_as_opt_u16, get_as_osk_domain_separator, get_legacy_osk_domain_separator,
};
use crate::{
    config::parse_from_toml::util::{get_as_opt_inline_table, get_as_opt_string},
    oldconfig::{Keypair, RosenpassPeerOskDomainSeparator},
};

use super::types::*;
pub use errors::{ParseError, ParseIssue, ParseWarning};
pub mod errors;
pub mod util;

impl RosenpassConfig {
    /// parses a TOML document into a [`RosenpassConfig`]
    ///
    /// - if successful, returns a [RosenpassConfig] and a list of warnings
    /// - if failing, returns a list of errors and warnings
    pub fn parse_from_toml(
        document: toml_edit::Document<String>,
        working_directory: &Path,
    ) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
        let mut warnings: Vec<ParseWarning> = Vec::new();
        let mut errors: Vec<ParseError> = Vec::new();
        let raw = document.raw();

        let get_array_of_tables =
            |name: &str| -> Result<&toml_edit::ArrayOfTables, Vec<ParseError>> {
                let item = document.get(name).ok_or_else(|| {
                    vec![ParseError::new(
                        raw,
                        document.span(),
                        format!("missing array of tables \"[[{name}]]\""),
                    )]
                })?;
                let return_value = item.as_array_of_tables().ok_or_else(|| {
                    vec![ParseError::new(
                        raw,
                        item.span(),
                        format!(
                            "item \"{name}\" {}",
                            "has wrong data type, must be array of tables"
                        ),
                    )]
                })?;
                Ok(return_value)
            };

        // ============================== [rosenpass] ==============================
        let mut our_listen_adresses = Vec::new();
        let mut verbosity: Option<Verbosity> = None;
        let mut our_keypair: Option<Keypair> = None;
        {
            let mut process_rosenpass_table = |table: &Table| {
                // our_listen_addresses
                if let Some(listen_addresses) =
                    process_result!(errors, get_as_array(raw, table, table.span(), "listen"))
                {
                    if listen_addresses.is_empty() {
                        warnings.push(ParseWarning::new(
                            raw,
                            listen_addresses.span(),
                            "listen addresses list is empty, defaulting to TODO".to_string(),
                        ));
                    }
                    for listen_address in listen_addresses.iter() {
                        let value = process_result!(
                            errors,
                            listen_address.as_str().ok_or_else(|| {
                                vec![ParseError::new(
                                    raw,
                                    listen_address.span(),
                                    "item in list has wrong data type: should be string"
                                        .to_string(),
                                )]
                            })
                        );
                        if let Some(value) = value {
                            let addr = process_result!(
                                errors,
                                std::net::SocketAddr::from_str(value).map_err(|err| {
                                    vec![ParseError::new(
                                        raw,
                                        listen_address.span(),
                                        err.to_string(),
                                    )]
                                })
                            );
                            if let Some(addr) = addr {
                                our_listen_adresses.push(addr);
                            }
                        }
                    }
                }
                // log_level
                verbosity = process_result!(
                    errors,
                    get_as_opt_log_level(raw, table, table.span(), "logging-level")
                )
                .flatten();

                // our_keys
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
                        our_keypair = Some(Keypair {
                            secret_key: secret.expect("unreachable"),
                            public_key: public.expect("unreachable"),
                        });
                    }
                }
            };
            if let Some(rosenpass_table) = document.get("rosenpass").and_then(|v| v.as_table()) {
                process_rosenpass_table(rosenpass_table);
            } else {
                process_rosenpass_table(document.as_table());
            }
        }
        // ============================== [[device]] ==============================
        let mut devices: Vec<WgDeviceConfig> = Vec::new();
        if let Some(device_tables) =
            process_result!(errors, get_array_of_tables("wireguard-devices"))
        {
            for table in device_tables {
                // TODO: remove unwrap()s
                let mut device_errors = {
                    let mut errors = Vec::new();

                    // name
                    let name =
                        process_result!(errors, get_as_string(raw, table, table.span(), "name"));

                    // enabled
                    let enabled = process_result!(
                        errors,
                        get_as_opt_bool(raw, table, table.span(), "enabled")
                    )
                    .flatten()
                    .unwrap_or(true);

                    // created_by
                    let created_by =
                        process_result!(errors, get_as_bool(raw, table, table.span(), "create",))
                            .map(|create| {
                                if !create {
                                    Some(WgDeviceCreateOptions::DoNotCreate)
                                } else {
                                    let mut inline_errors = Vec::new();

                                    // wg_listen_port
                                    let wg_listen_port = process_result!(
                                        inline_errors,
                                        get_as_opt_u16(raw, table, table.span(), "listen-port")
                                    )
                                    .flatten(); // defaults to `None`

                                    // wg_fwmark
                                    let wg_fwmark = process_result!(
                                        inline_errors,
                                        get_as_opt_u16(raw, table, table.span(), "fwmark")
                                    )
                                    .flatten(); // defaults to `None`

                                    // return
                                    errors.extend_from_slice(&inline_errors);
                                    inline_errors.is_empty().then(|| {
                                        WgDeviceCreateOptions::Create {
                                            wg_listen_port,
                                            wg_fwmark,
                                        }
                                    })
                                }
                            })
                            .flatten();

                    if errors.is_empty() {
                        devices.push(WgDeviceConfig {
                            name: name.expect("unreachable"),
                            enabled,
                            created_by: created_by.expect("unreachable"),
                        });
                    }
                    errors
                };
                errors.append(&mut device_errors);
            }
        }
        // ============================== [[peer]] ==============================
        let mut peers = Vec::new();
        if let Some(peer_tables) = process_result!(errors, get_array_of_tables("peers")) {
            for table in peer_tables {
                let mut peer_errors = Vec::new();

                let name =
                    process_result!(peer_errors, get_as_string(raw, table, table.span(), "name"));

                let enabled = process_result!(
                    peer_errors,
                    get_as_opt_bool(raw, table, table.span(), "enabled")
                )
                .flatten()
                .unwrap_or(true);

                // read public key (complicated due to downwards-compatibility)
                let their_pubkey = {
                    let mut pubkey_errors = Vec::new();
                    const PUBLIC_KEY_NAME: &'static str = "public_key";
                    const THEIR_KEYPAIR_NAME: &'static str = "their-keypair";

                    // read both key sources
                    let legacy_key_file = process_result!(
                        pubkey_errors,
                        get_as_opt_path_buf(raw, table, table.span(), PUBLIC_KEY_NAME)
                    )
                    .flatten();
                    let their_keypair = process_result!(
                        pubkey_errors,
                        get_as_opt_inline_table(raw, table, table.span(), THEIR_KEYPAIR_NAME)
                    )
                    .flatten();
                    let their_public_key = match (legacy_key_file, their_keypair) {
                        (Some(_), Some(_)) => {
                            pubkey_errors.push(ParseError::new(
                                raw,
                                table.span(),
                                format!(
                                    "keys \"{PUBLIC_KEY_NAME}\" and \"{THEIR_KEYPAIR_NAME}\" exclude each other and \"{PUBLIC_KEY_NAME}\" is deprecated",
                                ),
                            ));
                            None
                        }
                        (None, None) => {
                            pubkey_errors.push(ParseError::new(
                                raw,
                                table.span(),
                                format!("expected key \"{THEIR_KEYPAIR_NAME}\""),
                            ));
                            None
                        }
                        (Some(legacy_key_file), None) => Some(KeyFromDisk::File(legacy_key_file)),
                        (None, Some(their_keypair)) => {
                            // TODO: throw error if peer's secret key is present

                            const FILE_NAME: &'static str = "public-key-file";
                            const DIR_NAME: &'static str = "public-key-directory";

                            let file = process_result!(
                                pubkey_errors,
                                get_as_opt_path_buf(
                                    raw,
                                    their_keypair,
                                    their_keypair.span(),
                                    FILE_NAME
                                )
                            )
                            .flatten();
                            let directory = process_result!(
                                pubkey_errors,
                                get_as_opt_path_buf(
                                    raw,
                                    their_keypair,
                                    their_keypair.span(),
                                    DIR_NAME
                                )
                            )
                            .flatten();
                            match (file, directory) {
                                (Some(_), Some(_)) => {
                                    pubkey_errors.push(ParseError::new(
                                        raw,
                                        their_keypair.span(),
                                        format!("keys \"{FILE_NAME}\" and \"{DIR_NAME}\" exclude each other"),
                                    ));
                                    None
                                }
                                (None, None) => {
                                    pubkey_errors.push(ParseError::new(
                                        raw,
                                        their_keypair.span(),
                                        format!("expected key \"{FILE_NAME}\""),
                                    ));
                                    None
                                }
                                (Some(file), None) => Some(KeyFromDisk::File(file)),
                                (None, Some(dir)) => Some(KeyFromDisk::Directory(dir)),
                            }
                        }
                    };
                    peer_errors.extend_from_slice(&pubkey_errors);
                    their_public_key
                };

                let endpoint = process_result!(
                    peer_errors,
                    get_as_opt_socket_addr(raw, table, table.span(), "endpoint")
                )
                .flatten();

                // read preshared key source (complicated due to downwards-compatibility)
                // TODO: stuff into legacy-aware function similar to `get_legacy_osk_domain_separator`
                let preshared_key_source = {
                    const LEGACY_NAME: &str = "pre_shared_key";
                    const PSK_NAME: &str = "preshared-key";
                    let mut psk_errors = Vec::new();

                    let legacy_psk_file = process_result!(
                        psk_errors,
                        get_as_opt_path_buf(raw, table, table.span(), LEGACY_NAME)
                    )
                    .flatten();
                    let psk_table = process_result!(
                        psk_errors,
                        get_as_opt_psk_source(raw, table, table.span(), PSK_NAME)
                    )
                    .flatten();
                    let psk_source = match (legacy_psk_file, psk_table) {
                        (Some(_), Some(_)) => {
                            psk_errors.push(ParseError::new(
                                raw,
                                table.span(),
                                format!("keys \"{LEGACY_NAME}\" and \"{PSK_NAME}\" exlude each other and \"{LEGACY_NAME}\" is deprecated"),
                            ));
                            None
                        }
                        (None, None) => {
                            psk_errors.push(ParseError::new(
                                raw,
                                table.span(),
                                format!("expected key \"{PSK_NAME}\""),
                            ));
                            None
                        }
                        (Some(legacy_psk_file), None) => {
                            Some(PresharedKeySource::ReadFromFile(legacy_psk_file))
                        }
                        (None, Some(psk_table)) => Some(psk_table),
                    };
                    peer_errors.extend_from_slice(&psk_errors);
                    psk_source
                };
                let osk_domain_separator = process_result!(
                    peer_errors,
                    get_legacy_osk_domain_separator(raw, table, table.span())
                );

                if peer_errors.is_empty() {
                    peers.push(PeerConfig {
                        name: name.expect("unreachable"),
                        enabled,
                        their_public_key: their_pubkey.expect("unreachable"),
                        endpoint: endpoint.expect("unreachable"),
                        preshared_key: preshared_key_source,
                        osk_domain_separator: osk_domain_separator.expect("unreachable"),
                        output_to_file: None, //todo!(),
                        wireguard: None,      //todo!(),
                    })
                }
                errors.append(&mut peer_errors);
            }
        }
        // ============================== return ==============================
        if !errors.is_empty() {
            let mut issues: Vec<ParseIssue> = Vec::new();
            issues.extend(warnings.into_iter().map(ParseIssue::Warning));
            issues.extend(errors.into_iter().map(ParseIssue::Error));
            Err(issues)
        } else {
            Ok((
                RosenpassConfig {
                    our_listen_addresses: our_listen_adresses,
                    verbosity: verbosity.unwrap_or_default(),
                    our_keypair: our_keypair.expect("unreachable"),

                    supported_protocol_versions,
                    
                    #[cfg(feature = "experiment_api")]
                    api: todo!(),
                    wireguard_devices: devices,
                    peers,

                    parsed_from
                },
                warnings,
            ))
        }
    }
}
