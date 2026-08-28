use log::LevelFilter;
use toml_edit::Table;

use util::{
    get_as_crypto_algorithm_choice, get_as_flat_device_managed_by_choice, get_as_opt_log_level,
    get_as_string,
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
    ) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
        let mut warnings: Vec<ParseWarning> = Vec::new();
        let mut errors: Vec<ParseError> = Vec::new();
        let raw = document.raw();

        macro_rules! process_result {
            ($result: expr) => {
                $result.map(|v| Some(v)).unwrap_or_else(|err| {
                    errors.push(err);
                    None
                })
            };
        }

        // ============================== [rosenpass] ==============================
        let our_listen_adresses = Vec::new();
        let mut logging_level: Option<LevelFilter> = None;
        {
            let mut process_rosenpass_table = |table: &Table| {
                logging_level = process_result!(get_as_opt_log_level(
                    document.raw(),
                    table,
                    table.span(),
                    "logging-level"
                ))
                .flatten();

                todo!()
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
        for table in document
            .get("device")
            .unwrap()
            .as_array_of_tables()
            .unwrap()
        {
            // TODO: remove unwrap()s
            let mut device_errors = {
                let mut errors = Vec::new();
                let name = process_result!(get_as_string(raw, table, table.span(), "name"));
                let managed_by = process_result!(get_as_flat_device_managed_by_choice(
                    raw,
                    table,
                    table.span(),
                    "managed-by",
                ))
                .map(|managed_by| match managed_by {
                    FlatDeviceManagedByChoice::Wireguard => Some(DeviceManagedByChoice::Wireguard),
                    FlatDeviceManagedByChoice::Rosenpass => {
                        todo!("read additional data")
                    }
                })
                .flatten();
                if errors.is_empty() {
                    devices.push(DeviceConfig {
                        name: name.expect("unreachable"),
                        managed_by: managed_by.expect("unreachable"),
                        path_to_wg_binary: todo!(),
                    });
                }
                errors
            };
            errors.append(&mut device_errors);
        }

        // ============================== [[peer]] ==============================
        let mut peers = Vec::new();
        for table in document
            .get("peer")
            .unwrap()
            .as_array_of_tables()
            // TODO: remove unwrap()s
            .unwrap()
        {
            let mut peer_errors = {
                let mut errors = Vec::new();
                let name = process_result!(get_as_string(raw, table, table.span(), "name"));
                let algorithm = process_result!(get_as_crypto_algorithm_choice(
                    raw,
                    table,
                    table.span(),
                    "algorithm"
                ));
                if errors.is_empty() {
                    peers.push(PeerConfig {
                        name: name.expect("unreachable"),
                        algorithm: algorithm.expect("unreachable"),
                        public_key_file: todo!(),
                        endpoint: todo!(),
                        preshared_key_file: todo!(),
                        osk_domain_separator: todo!(),
                        output_to_file: todo!(),
                        wireguard: todo!(),
                    })
                }
                errors
            };
            errors.append(&mut peer_errors);
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
                    our_keys: todo!(),
                    protocol_version: todo!(),
                    log_level: logging_level.unwrap_or(LevelFilter::Info),
                    logging_output_file: todo!(),
                    #[cfg(feature = "experiment_api")]
                    api: todo!(),
                    devices: todo!(),
                    peers: todo!(),
                },
                warnings,
            ))
        }
    }
}
