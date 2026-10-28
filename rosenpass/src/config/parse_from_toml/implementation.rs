//! TODO: doc

#[cfg(feature = "experiment_api")]
use super::util::get_as_opt_api_config;
use super::util::{
    get_as_bool, get_as_opt_bool, get_as_opt_device_wireguard_options, get_as_opt_verbosity_level,
    get_as_string, get_legacy_osk_domain_separator,
};
use crate::config::parse_from_toml::util::{
    GetKeyValueSpan, GuaranteedUnwrap, ProcessParseResult, default_peer_name, deny_illegal_keys,
    get_as_opt_config_file_version, get_as_opt_hashset_protocol_version, get_as_opt_string,
    get_as_opt_vec_socket_addr, get_legacy_key_output, get_legacy_keypair_from_disk,
    get_legacy_psk_source, get_legacy_public_key_from_disk, get_legacy_wireguard,
    get_opt_array_of_tables,
};
use crate::oldconfig::Verbosity;
use crate::protocol::ProtocolVersion;
use std::{collections::HashSet, path::Path};
use toml_edit::Table;

use super::super::types::*;
pub use super::errors::{ParseError, ParseIssue, ParseWarning};

impl RosenpassConfig {
    /// parses a TOML document into a [`RosenpassConfig`]
    ///
    /// - if successful, returns a [RosenpassConfig] and a list of warnings
    /// - if failing, returns a list of errors and warnings
    ///
    /// **NOTE:** all paths (e.g. to key files) are relative to the TOML file's parent directory.
    /// Use [`ResolvePathRelativeToConfig`]. See [`RosenpassConfig`]'s documentation for a code
    /// example.
    ///
    /// - TODO: many calls to `get_as_inline_table` could be replaced with `get_as_table_like` for a
    ///   more generic TOML-idiomatic semantic. However, this might need thorough discussion
    ///   upfront.
    pub fn parse_from_toml(
        document: &toml_edit::Document<String>,
        file_path: &Path,
    ) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
        let mut warnings: Vec<ParseWarning> = Vec::new();
        let mut errors: Vec<ParseError> = Vec::new();
        let raw = document.raw();
        let working_directory = file_path
            .parent()
            .expect("specified file path has no parent directory");

        const WG_DEVICES: &str = "wireguard-devices";
        const PEERS: &str = "peers";
        const ROSSENPASS: &str = "rosenpass";

        let root_keys_except_rosenpass = vec![WG_DEVICES, PEERS];
        let root_keys = {
            let mut keys = vec![ROSSENPASS];
            keys.extend_from_slice(&root_keys_except_rosenpass);
            keys
        };
        // ============================== [rosenpass] ==============================
        struct RosenpassTable {
            our_listen_addresses: Vec<SocketAddr>,
            verbosity: Verbosity,
            our_keypair: PqKeypairSource,
            supported_protocol_versions: HashSet<ProtocolVersion>,
            config_file_version: TomlConfigFileVersion,
            #[cfg(feature = "experiment_api")]
            api: ApiConfig,
        }

        let rosenpass_table = {
            let mut process_rosenpass_table =
                |table: &Table,
                 is_document_root_table: bool|
                 -> Result<RosenpassTable, Vec<ParseError>> {
                    let mut errors = Vec::new();

                    const LISTEN: &str = "listen";
                    const VERBOSITY: &str = "verbosity";

                    const OUR_KEYPAIR: &str = "our-keypair";
                    const LEGACY_OUR_SECRET_KEY: &str = "secret_key";
                    const LEGACY_OUR_PUBLIC_KEY: &str = "public_key";

                    const SUPPORTED_PROTOCOL_VERSIONS: &str = "supported-protocol-versions";
                    const CONFIG_FILE_VERSION: &str = "config-file-version";
                    const API: &str = "api";

                    let mut legal_keys = vec![
                        LISTEN,
                        VERBOSITY,
                        OUR_KEYPAIR,
                        LEGACY_OUR_SECRET_KEY,
                        LEGACY_OUR_PUBLIC_KEY,
                        SUPPORTED_PROTOCOL_VERSIONS,
                        CONFIG_FILE_VERSION,
                        API,
                    ];
                    if is_document_root_table {
                        legal_keys.extend_from_slice(&root_keys_except_rosenpass);
                    }
                    deny_illegal_keys(raw, file_path, table, legal_keys)
                        .process_parse_result(&mut errors);

                    #[cfg(not(feature = "experiment_api"))]
                    if let Some(key) = table.key(API) {
                        warnings.push(ParseWarning::new_ext(
                            raw,
                            file_path,
                            key.span(),
                            "feature \"experiment_api\" is not enabled in this Rosenpass build",
                            "experimental feature ignored",
                        ));
                    }

                    // our listen addresses
                    let our_listen_addresses =
                        get_as_opt_vec_socket_addr(raw, file_path, table, table.span(), LISTEN)
                            .process_parse_result(&mut errors)
                            .flatten()
                            .unwrap_or_default(); // default to empty list
                    // warn if listen addresses are empty
                    if our_listen_addresses.is_empty() {
                        // span: use key-value pair's span, fall back onto table span
                        let span = table.get_key_value_span(LISTEN).or_else(|| table.span());
                        warnings.push(ParseWarning::new_ext(
                            raw,
                            file_path,
                            span,
                            format!(
                                "{}, defaulting to all interfaces and a random ephemeral port",
                                "listen addresses list is empty"
                            ),
                            "empty listen addresses list occurs here",
                        ));
                    }

                    // log_level
                    let verbosity =
                        get_as_opt_verbosity_level(raw, file_path, table, table.span(), VERBOSITY)
                            .process_parse_result(&mut errors)
                            .flatten()
                            .unwrap_or_default();

                    // our_keys
                    let our_keypair = get_legacy_keypair_from_disk(
                        raw,
                        file_path,
                        table,
                        table.span(),
                        LEGACY_OUR_SECRET_KEY,
                        LEGACY_OUR_PUBLIC_KEY,
                        OUR_KEYPAIR,
                    )
                    .process_parse_result(&mut errors);

                    // supported protocol versions
                    let supported_protocol_versions = get_as_opt_hashset_protocol_version(
                        raw,
                        file_path,
                        table,
                        table.span(),
                        SUPPORTED_PROTOCOL_VERSIONS,
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
                        CONFIG_FILE_VERSION,
                    )
                    .process_parse_result(&mut errors)
                    .flatten()
                    .unwrap_or_default();

                    // api config
                    #[cfg(feature = "experiment_api")]
                    let api_config = {
                        get_as_opt_api_config(raw, file_path, table, table.span(), API)
                            .process_parse_result(&mut errors)
                            .flatten()
                            .unwrap_or_default()
                    };

                    if !errors.is_empty() {
                        return Err(errors);
                    }
                    Ok(RosenpassTable {
                        our_listen_addresses,
                        verbosity,
                        our_keypair: our_keypair.guaranteed_unwrap(),
                        supported_protocol_versions,
                        config_file_version,
                        #[cfg(feature = "experiment_api")]
                        api: api_config,
                    })
                };
            if let Some(rosenpass_table) = document.get("rosenpass").and_then(|v| v.as_table()) {
                // parse the `[rosenpass]` table (not the root document) – thus, we need to deny
                // illegal keys manually
                deny_illegal_keys(raw, file_path, document.as_table(), root_keys)
                    .process_parse_result(&mut errors);
                process_rosenpass_table(rosenpass_table, false)
            } else {
                // parse the root document – `process_rosenpass_table` will exclude illegal keys
                process_rosenpass_table(document.as_table(), true)
            }
        };
        let rosenpass_table = rosenpass_table.process_parse_result(&mut errors);
        // ============================== [[wireguard-devices]] ==============================
        let mut wireguard_devices: Vec<WgDeviceConfig> = Vec::new();
        if let Some(device_tables) = get_opt_array_of_tables(raw, file_path, document, WG_DEVICES)
            .process_parse_result(&mut errors)
            .flatten()
        {
            for table in device_tables {
                let mut device_errors = {
                    let mut errors = Vec::new();

                    const NAME: &str = "name";
                    const ENABLED: &str = "enabled";
                    const CREATE: &str = "create";
                    const WG_OPTIONS: &str = "wireguard-options";

                    deny_illegal_keys(
                        raw,
                        file_path,
                        table,
                        vec![NAME, ENABLED, CREATE, WG_OPTIONS],
                    )
                    .process_parse_result(&mut errors);

                    // name
                    let name = get_as_string(raw, file_path, table, table.span(), NAME)
                        .process_parse_result(&mut errors);

                    // enabled
                    let enabled = get_as_opt_bool(raw, file_path, table, table.span(), ENABLED)
                        .process_parse_result(&mut errors)
                        .flatten()
                        .unwrap_or(true);

                    // created_by
                    let created_by = get_as_bool(raw, file_path, table, table.span(), CREATE)
                        .process_parse_result(&mut errors)
                        .and_then(|create| {
                            if !create {
                                Some(WgDeviceCreateOptions::DoNotCreate)
                            } else {
                                let options = get_as_opt_device_wireguard_options(
                                    raw,
                                    file_path,
                                    table,
                                    table.span(),
                                    WG_OPTIONS,
                                )
                                .process_parse_result(&mut errors)
                                .flatten()
                                .unwrap_or_default(); // defaults to empty options
                                Some(WgDeviceCreateOptions::Create(options))
                            }
                        });

                    if errors.is_empty() {
                        wireguard_devices.push(WgDeviceConfig {
                            name: name.guaranteed_unwrap(),
                            enabled,
                            created_by: created_by.guaranteed_unwrap(),
                        });
                    }
                    errors
                };
                errors.append(&mut device_errors);
            }
        }

        // ============================== [[peers]] ==============================
        let mut peers = Vec::new();
        if let Some(peer_tables) = get_opt_array_of_tables(raw, file_path, document, PEERS)
            .process_parse_result(&mut errors)
            .flatten()
        {
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

                const LEGACY_KEY_OUTPUT: &str = "key_out";
                const KEY_OUTPUT_TABLE: &str = "key-out";

                const LEGACY_WG_DEVICE: &str = "device";
                const LEGACY_THEIR_WG_PUBKEY: &str = "peer";
                const LEGACY_OUR_WG_PUBKEY: &str = "our_wg_pubkey";
                const LEGACY_WG_EXTRA_PARAMS: &str = "extra_params";
                const LEGACY_WG_EXCHANGE_COMMAND: &str = "exchange_command";
                const WG_TABLE: &str = "wireguard";

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
                        LEGACY_KEY_OUTPUT,
                        KEY_OUTPUT_TABLE,
                        LEGACY_WG_DEVICE,
                        LEGACY_THEIR_WG_PUBKEY,
                        LEGACY_OUR_WG_PUBKEY,
                        LEGACY_WG_EXTRA_PARAMS,
                        LEGACY_WG_EXCHANGE_COMMAND,
                        WG_TABLE,
                    ],
                )
                .process_parse_result(&mut peer_errors);

                // name
                let name = get_as_opt_string(raw, file_path, table, table.span(), NAME)
                    .process_parse_result(&mut peer_errors)
                    .flatten()
                    .unwrap_or_else(|| default_peer_name(peers.len()));

                // enabled
                let enabled = get_as_opt_bool(raw, file_path, table, table.span(), ENABLED)
                    .process_parse_result(&mut peer_errors)
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

                let preshared_key = get_legacy_psk_source(
                    raw,
                    file_path,
                    table,
                    table.span(),
                    LEGACY_PSK,
                    PSK_TABLE,
                )
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

                // key output option: write to file
                let output_to_file = get_legacy_key_output(
                    raw,
                    file_path,
                    table,
                    table.span(),
                    LEGACY_KEY_OUTPUT,
                    KEY_OUTPUT_TABLE,
                )
                .process_parse_result(&mut peer_errors)
                // make this item optional
                .transpose()
                .unwrap_or(None);

                // wireguard protocol extension
                let wireguard = get_legacy_wireguard(
                    raw,
                    file_path,
                    table,
                    table.span(),
                    LEGACY_WG_DEVICE,
                    LEGACY_THEIR_WG_PUBKEY,
                    LEGACY_OUR_WG_PUBKEY,
                    LEGACY_WG_EXTRA_PARAMS,
                    LEGACY_WG_EXCHANGE_COMMAND,
                    WG_TABLE,
                )
                .process_parse_result(&mut peer_errors)
                // make this item optional
                .transpose()
                .unwrap_or(None);

                if peer_errors.is_empty() {
                    peers.push(PeerConfig {
                        name,
                        enabled,
                        their_public_key: their_pubkey.guaranteed_unwrap(),
                        endpoint,
                        preshared_key,
                        osk_domain_separator: osk_domain_separator.guaranteed_unwrap(),
                        output_to_file,
                        wireguard,
                    })
                }
                errors.append(&mut peer_errors);
            }
        }
        // warn if no peers defined
        if peers.is_empty() {
            warnings.push(ParseWarning::new_ext(
                raw,
                file_path,
                None,
                "configuration contains no peers, making it somewhat useless",
                "add some [[peers]] tables somewhere",
            ));
        }

        // ============================== return ==============================
        if !errors.is_empty() {
            let mut issues: Vec<ParseIssue> = Vec::new();
            issues.extend(warnings.into_iter().map(ParseIssue::Warning));
            issues.extend(errors.into_iter().map(ParseIssue::Error));
            Err(issues)
        } else {
            let rosenpass_table = rosenpass_table.guaranteed_unwrap();

            let parsed_from = ConfigSource::TomlFile(ConfigSourceTomlFile {
                file_path: file_path.to_path_buf(),
                document: document.clone().into(), // TODO (fancy): this could be a reference
                warnings: warnings.clone(),
                file_version: rosenpass_table.config_file_version,
            });
            Ok((
                RosenpassConfig {
                    our_listen_addresses: rosenpass_table.our_listen_addresses,
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
