use crate::config::parse_from_toml::util::{
    ProcessParseResult, default_peer_name, deny_illegal_keys, get_as_opt_config_file_version,
    get_as_opt_hashset_protocol_version, get_as_opt_string, get_legacy_keypair_from_disk,
    get_legacy_psk_source, get_legacy_public_key_from_disk,
};
use crate::oldconfig::Verbosity;
use crate::protocol::ProtocolVersion;
use std::str::FromStr;
use std::{collections::HashSet, path::Path};
use toml_edit::{ArrayOfTables, Table};
#[cfg(feature = "experiment_api")]
use util::get_as_opt_api_config;
use util::{
    get_as_array, get_as_bool, get_as_opt_bool, get_as_opt_inline_table, get_as_opt_path_buf,
    get_as_opt_psk_source, get_as_opt_u16, get_as_opt_verbosity_level, get_as_string,
    get_legacy_osk_domain_separator, process_results,
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
        document: &toml_edit::Document<String>,
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
                        file_path,
                        document.span(),
                        format!("missing array of tables \"[[{name}]]\""),
                    )]
                })?;
                let return_value = item.as_array_of_tables().ok_or_else(|| {
                    vec![ParseError::new(
                        raw,
                        file_path,
                        item.span(),
                        format!(
                            "item \"{name}\" {}",
                            "has wrong data type, must be array of tables"
                        ),
                    )]
                })?;
                Ok(return_value)
            };
        let get_opt_array_of_tables =
            |name: &str| -> Result<Option<&toml_edit::ArrayOfTables>, Vec<ParseError>> {
                match document.get(name) {
                    None => Ok(None),
                    Some(item) => {
                        let array: &ArrayOfTables = item.as_array_of_tables().ok_or_else(|| {
                            vec![ParseError::new(
                                raw,
                                file_path,
                                item.span(),
                                format!(
                                    "item \"{name}\" {}",
                                    "has wrong data type, must be array of tables"
                                ),
                            )]
                        })?;
                        Ok(Some(array))
                    }
                }
            };

        // ============================== [rosenpass] ==============================
        struct RosenpassTable {
            our_listen_adresses: Vec<SocketAddr>,
            verbosity: Verbosity,
            our_keypair: PqKeypairSource,
            supported_protocol_versions: HashSet<ProtocolVersion>,
            config_file_version: TomlConfigFileVersion,
            #[cfg(feature = "experiment_api")]
            api: ApiConfig,
        }
        let rosenpass_table = {
            let mut process_rosenpass_table =
                |table: &Table| -> Result<RosenpassTable, Vec<ParseError>> {
                    let mut errors = Vec::new();

                    // our_listen_addresses
                    // TODO: put this code into `util` module
                    let our_listen_address = process_results!(
                        errors,
                        get_as_array(raw, file_path, table, table.span(), "listen")
                    )
                    .map(|listen_addresses| {
                        let mut return_value = Vec::new();
                        if listen_addresses.is_empty() {
                            warnings.push(ParseWarning::new(
                                raw,
                                file_path,
                                listen_addresses.span(),
                                "listen addresses list is empty, defaulting to all interfaces and a random ephemeral port".to_string(),
                            ));
                        }
                        for listen_address in listen_addresses.iter() {
                            let value = process_results!(
                                errors,
                                listen_address.as_str().ok_or_else(|| {
                                    vec![ParseError::new(
                                        raw,
                                        file_path,
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
                                            file_path,
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
                    let verbosity = get_as_opt_verbosity_level(
                        raw,
                        file_path,
                        table,
                        table.span(),
                        "logging-level",
                    )
                    .process_parse_result(&mut errors)
                    .flatten()
                    .unwrap_or_default();

                    // our_keys
                    let our_keypair = process_results!(
                        errors,
                        get_legacy_keypair_from_disk(
                            raw,
                            file_path,
                            table,
                            table.span(),
                            "our-keypair"
                        )
                    );

                    // supported protocol versions
                    let supported_protocol_versions = get_as_opt_hashset_protocol_version(
                        raw,
                        file_path,
                        table,
                        table.span(),
                        "supported-protocol-versions",
                    )
                    .process_parse_result(&mut errors)
                    .flatten()
                    .unwrap_or_else(ProtocolVersion::all_supported_by_default);

                    // config file version
                    let config_file_version = get_as_opt_config_file_version(
                        raw,
                        file_path,
                        table,
                        table.span(),
                        "config-file-version",
                    )
                    .process_parse_result(&mut errors)
                    .flatten()
                    .unwrap_or_default();

                    // api config
                    #[cfg(feature = "experiment_api")]
                    let api_config = {
                        get_as_opt_api_config(raw, file_path, table, table.span(), "api")
                            .process_parse_result(&mut errors)
                            .flatten()
                            .unwrap_or_default()
                    };

                    if !errors.is_empty() {
                        return Err(errors);
                    }
                    Ok(RosenpassTable {
                        our_listen_adresses: our_listen_address.expect("unreachable"),
                        verbosity,
                        our_keypair: our_keypair.expect("unreachable"),
                        supported_protocol_versions,
                        config_file_version,
                        #[cfg(feature = "experiment_api")]
                        api: api_config,
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
        if let Some(device_tables) = get_opt_array_of_tables("wireguard-devices")
            .process_parse_result(&mut errors)
            .flatten()
        {
            for table in device_tables {
                // TODO: remove unwrap()s
                let mut device_errors = {
                    let mut errors = Vec::new();

                    // name
                    let name = process_results!(
                        errors,
                        get_as_string(raw, file_path, table, table.span(), "name")
                    );

                    // enabled
                    let enabled = process_results!(
                        errors,
                        get_as_opt_bool(raw, file_path, table, table.span(), "enabled")
                    )
                    .flatten()
                    .unwrap_or(true);

                    // created_by
                    let created_by = process_results!(
                        errors,
                        get_as_bool(raw, file_path, table, table.span(), "create",)
                    )
                    .map(|create| {
                        if !create {
                            Some(WgDeviceCreateOptions::DoNotCreate)
                        } else {
                            let mut inline_errors = Vec::new();

                            // wg_listen_port
                            let wg_listen_port = process_results!(
                                inline_errors,
                                get_as_opt_u16(raw, file_path, table, table.span(), "listen-port")
                            )
                            .flatten(); // defaults to `None`

                            // wg_fwmark
                            let wg_fwmark = process_results!(
                                inline_errors,
                                get_as_opt_u16(raw, file_path, table, table.span(), "fwmark")
                            )
                            .flatten(); // defaults to `None`

                            // return
                            errors.extend_from_slice(&inline_errors);
                            inline_errors
                                .is_empty()
                                .then_some(WgDeviceCreateOptions::Create {
                                    wg_listen_port,
                                    wg_fwmark,
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

                const NAME: &str = "name";
                const ENABLED: &str = "enabled";
                const LEGACY_THEIR_PUBKEY: &str = "public_key";
                const THEIR_PUBKEY_TABLE: &str = "their-keypair";
                const ENDPOINT: &str = "endpoint";

                const LEGACY_PSK: &str = "pre_shared_key";
                const PSK_TABLE: &str = "preshared-key";

                const LEGACY_OSK_ORG: &str = "osk_organization";
                const LEGACY_OSK_LABELS: &str = "osk_label";
                const OSK_TABLE: &str = "osk-domain-separator";

                deny_illegal_keys(
                    raw,
                    file_path,
                    table,
                    vec![
                        NAME,
                        ENABLED,
                        LEGACY_THEIR_PUBKEY,
                        THEIR_PUBKEY_TABLE,
                        ENDPOINT,
                        LEGACY_PSK,
                        PSK_TABLE,
                        LEGACY_OSK_ORG,
                        LEGACY_OSK_LABELS,
                        OSK_TABLE,
                    ],
                )
                .process_parse_result(&mut peer_errors);

                // name
                let name = get_as_opt_string(raw, file_path, table, table.span(), NAME)
                    .process_parse_result(&mut peer_errors)
                    .flatten()
                    .unwrap_or_else(|| default_peer_name(peers.len()));

                // enabled
                let enabled = process_results!(
                    peer_errors,
                    get_as_opt_bool(raw, file_path, table, table.span(), ENABLED)
                )
                .flatten()
                .unwrap_or(true);

                // their public key
                let their_pubkey = get_legacy_public_key_from_disk(
                    raw,
                    file_path,
                    table,
                    table.span(),
                    LEGACY_THEIR_PUBKEY,
                    THEIR_PUBKEY_TABLE,
                )
                .process_parse_result(&mut peer_errors)
                .transpose()
                .process_parse_result(&mut peer_errors)
                .flatten();

                // endpoint
                let endpoint = get_as_opt_string(raw, file_path, table, table.span(), ENDPOINT)
                    .process_parse_result(&mut peer_errors)
                    .flatten();

                let preshared_key =
                    get_legacy_psk_source(raw, file_path, table, table.span(), LEGACY_PSK, PSK_TABLE)
                        .process_parse_result(&mut peer_errors)
                        // if PSK source is not present, just default to `None`:
                        .transpose()
                        .ok()
                        .flatten();

                // OSK domain separator
                let osk_domain_separator = get_legacy_osk_domain_separator(
                    raw,
                    file_path,
                    table,
                    table.span(),
                    LEGACY_OSK_ORG,
                    LEGACY_OSK_LABELS,
                    OSK_TABLE,
                )
                .process_parse_result(&mut peer_errors);

                if peer_errors.is_empty() {
                    peers.push(PeerConfig {
                        name,
                        enabled,
                        their_public_key: their_pubkey.expect("unreachable"),
                        endpoint,
                        preshared_key,
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
                document: document.clone(), // TODO: this could be a reference
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
                    api: rosenpass_table.api,
                    wireguard_devices,
                    peers,

                    parsed_from,
                },
                warnings,
            ))
        }
    }
}
