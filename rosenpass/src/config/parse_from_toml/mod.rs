use crate::config::parse_from_toml::util::{
    ProcessParseResult, get_as_hashset_protocol_version, get_as_opt_config_file_version,
    get_legacy_keypair_from_disk,
};
use crate::oldconfig::Verbosity;
use crate::protocol::ProtocolVersion;
use std::str::FromStr;
use std::{collections::HashSet, path::Path};
use toml_edit::Table;
use util::{
    get_as_array, get_as_bool, get_as_opt_bool, get_as_opt_inline_table, get_as_opt_path_buf,
    get_as_opt_psk_source, get_as_opt_socket_addr, get_as_opt_u16, get_as_opt_verbosity_level,
    get_as_string, get_legacy_osk_domain_separator, process_results,
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
    ///
    /// TODO: use `Option::unwrap` (or custom implementation) instead of `.unwrap()`
    /// TODO: resolve paths
    pub fn parse_from_toml(
        document: toml_edit::Document<String>,
        file_path: &Path,
    ) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
        let mut warnings: Vec<ParseWarning> = Vec::new();
        let mut errors: Vec<ParseError> = Vec::new();
        let raw = document.raw();
        let working_directory = file_path
            .parent()
            .expect("specified file path has no parent");

        // TODO: put this into `util` module
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
        struct RosenpassTable {
            our_listen_adresses: Vec<SocketAddr>,
            verbosity: Verbosity,
            our_keypair: PqKeypairSource,
            supported_protocol_versions: HashSet<ProtocolVersion>,
            config_file_version: TomlConfigFileVersion,
        }
        let rosenpass_table = {
            let mut process_rosenpass_table =
                |table: &Table| -> Result<RosenpassTable, Vec<ParseError>> {
                    let mut errors = Vec::new();

                    // our_listen_addresses
                    // TODO: put this code into `util` module
                    let our_listen_address =
                        process_results!(errors, get_as_array(raw, table, table.span(), "listen"))
                            .map(|listen_addresses| {
                                let mut return_value = Vec::new();
                                if listen_addresses.is_empty() {
                                    warnings.push(ParseWarning::new(
                                        raw,
                                        listen_addresses.span(),
                                        "listen addresses list is empty, defaulting to TODO"
                                            .to_string(),
                                    ));
                                }
                                for listen_address in listen_addresses.iter() {
                                    let value = process_results!(
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
                                        let addr = process_results!(
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
                                            return_value.push(addr);
                                        }
                                    }
                                }
                                return_value
                            });

                    // log_level
                    let verbosity = process_results!(
                        errors,
                        get_as_opt_verbosity_level(raw, table, table.span(), "logging-level")
                    )
                    .flatten();

                    // our_keys
                    let our_keypair = process_results!(
                        errors,
                        get_legacy_keypair_from_disk(raw, table, table.span(), "our-keypair")
                    );

                    // supported protocol versions
                    let supported_protocol_version = get_as_hashset_protocol_version(
                        raw,
                        table,
                        table.span(),
                        "supported-protocol-versions",
                    )
                    .process_parse_result(&mut errors);

                    // config file version
                    let config_file_version = get_as_opt_config_file_version(
                        raw,
                        table,
                        table.span(),
                        "config-file-version",
                    )
                    .process_parse_result(&mut errors)
                    .flatten()
                    .unwrap_or_default();

                    if !errors.is_empty() {
                        return Err(errors);
                    }
                    Ok(RosenpassTable {
                        our_listen_adresses: our_listen_address.expect("unreachable"),
                        verbosity: verbosity.expect("unreachable"),
                        our_keypair: our_keypair.expect("unreachable"),
                        supported_protocol_versions: supported_protocol_version
                            .expect("unreachable"),
                        config_file_version,
                    })
                };
            if let Some(rosenpass_table) = document.get("rosenpass").and_then(|v| v.as_table()) {
                process_rosenpass_table(rosenpass_table)
            } else {
                process_rosenpass_table(document.as_table())
            }
        };
        let rosenpass_table = process_results!(errors, rosenpass_table);
        // ============================== [[wireguard-devices]] ==============================
        let mut wireguard_devices: Vec<WgDeviceConfig> = Vec::new();
        if let Some(device_tables) =
            process_results!(errors, get_array_of_tables("wireguard-devices"))
        {
            for table in device_tables {
                // TODO: remove unwrap()s
                let mut device_errors = {
                    let mut errors = Vec::new();

                    // name
                    let name =
                        process_results!(errors, get_as_string(raw, table, table.span(), "name"));

                    // enabled
                    let enabled = process_results!(
                        errors,
                        get_as_opt_bool(raw, table, table.span(), "enabled")
                    )
                    .flatten()
                    .unwrap_or(true);

                    // created_by
                    let created_by =
                        process_results!(errors, get_as_bool(raw, table, table.span(), "create",))
                            .map(|create| {
                                if !create {
                                    Some(WgDeviceCreateOptions::DoNotCreate)
                                } else {
                                    let mut inline_errors = Vec::new();

                                    // wg_listen_port
                                    let wg_listen_port = process_results!(
                                        inline_errors,
                                        get_as_opt_u16(raw, table, table.span(), "listen-port")
                                    )
                                    .flatten(); // defaults to `None`

                                    // wg_fwmark
                                    let wg_fwmark = process_results!(
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
                        wireguard_devices.push(WgDeviceConfig {
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
        // ============================== [[peers]] ==============================
        let mut peers = Vec::new();
        if let Some(peer_tables) = process_results!(errors, get_array_of_tables("peers")) {
            for table in peer_tables {
                let mut peer_errors = Vec::new();

                let name =
                    process_results!(peer_errors, get_as_string(raw, table, table.span(), "name"));

                let enabled = process_results!(
                    peer_errors,
                    get_as_opt_bool(raw, table, table.span(), "enabled")
                )
                .flatten()
                .unwrap_or(true);

                // read public key (complicated due to downwards-compatibility)
                let their_pubkey: Option<PublicPqKeySource> = {
                    let mut pubkey_errors = Vec::new();
                    const PUBLIC_KEY_NAME: &str = "public_key";
                    const THEIR_KEYPAIR_NAME: &str = "their-keypair";

                    // read both key sources
                    let legacy_key_file = process_results!(
                        pubkey_errors,
                        get_as_opt_path_buf(raw, table, table.span(), PUBLIC_KEY_NAME)
                    )
                    .flatten();
                    let their_keypair = process_results!(
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
                                    "keys \"{PUBLIC_KEY_NAME}\" and \"{THEIR_KEYPAIR_NAME}\" are mutually exclusive and \"{PUBLIC_KEY_NAME}\" is deprecated",
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
                        (Some(legacy_key_file), None) => Some(PublicPqKeySource::new(
                            <PublicPqKeySource as HasInnerType>::InnerType::File(legacy_key_file),
                        )),
                        (None, Some(their_keypair)) => {
                            // TODO: throw error if peer's secret key is present

                            const FILE_NAME: &str = "public-key-file";
                            const DIR_NAME: &str = "public-key-directory";

                            let file = process_results!(
                                pubkey_errors,
                                get_as_opt_path_buf(
                                    raw,
                                    their_keypair,
                                    their_keypair.span(),
                                    FILE_NAME
                                )
                            )
                            .flatten();
                            let directory = process_results!(
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
                                        format!("keys \"{FILE_NAME}\" and \"{DIR_NAME}\" are mutually exclusive"),
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
                                (Some(file), None) => Some(PublicPqKeySource::new(
                                    <PublicPqKeySource as HasInnerType>::InnerType::File(file),
                                )),
                                (None, Some(dir)) => Some(PublicPqKeySource::new(
                                    <PublicPqKeySource as HasInnerType>::InnerType::Directory(dir),
                                )),
                            }
                        }
                    };
                    peer_errors.extend_from_slice(&pubkey_errors);
                    their_public_key
                };

                let endpoint = process_results!(
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

                    let legacy_psk_file = process_results!(
                        psk_errors,
                        get_as_opt_path_buf(raw, table, table.span(), LEGACY_NAME)
                    )
                    .flatten();
                    let psk_table = process_results!(
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
                let osk_domain_separator = process_results!(
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
            let rosenpass_table = rosenpass_table.expect("unreachable");

            let parsed_from = ConfigSource::TomlFile(ConfigSourceTomlFile {
                file_path: file_path.to_path_buf(),
                document,
                warnings: warnings.clone(),
                file_version: rosenpass_table.config_file_version,
            });
            Ok((
                RosenpassConfig {
                    our_listen_addresses: rosenpass_table.our_listen_adresses,
                    verbosity: rosenpass_table.verbosity,
                    our_keypair: rosenpass_table.our_keypair,
                    supported_protocol_versions: rosenpass_table.supported_protocol_versions,

                    #[cfg(feature = "experiment_api")]
                    api: todo!(),
                    wireguard_devices,
                    peers,

                    parsed_from,
                },
                warnings,
            ))
        }
    }
}
