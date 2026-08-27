use std::{fmt::Debug, marker::PhantomData};

use toml_edit::Table;

use super::*;

/// converts a span from `toml_edit` into a line number and column number
pub(crate) fn resolve_span(raw: &str, span: &std::ops::Range<usize>) -> Option<(usize, usize)> {
    let foo = raw.get(0..span.start)?.split("\n").collect::<Vec<_>>();
    Some((foo.len(), foo.last().unwrap().len() + 1))
}
/// gets the value in `table` associated with `key` or returns an [`Err`] if the key does not exist within the table
///
/// - `file` is a reference to the file holding the `table` and is only required to format the error message in case of a missing key
/// - `table_span` is the location of the `table` within the TOML `file` and is only required to format the error message in case of a missing key
fn get_item<'a>(
    raw: &str,
    table: &'a Table,
    table_span: Option<&std::ops::Range<usize>>,
    key: &str,
) -> Result<&'a toml_edit::Item, ParseError> {
    table.get(key).ok_or_else(|| {
        let location = table_span
            .as_ref()
            .map(|span| resolve_span(raw, span))
            .flatten();
        ParseError {
            line: location.map(|l| l.0).unwrap_or(1),
            column: location.map(|l| l.1).unwrap_or(1),
            message: format!("require key \"{key}\""),
            _kind: Default::default(),
        }
    })
}
macro_rules! get_as_type_generator {
    ($fn_name: ident,$opt_fn_name: ident, $type_: ty, $getter: ident, $mapper: expr) => {
        #[allow(dead_code)]
        fn $fn_name<'a>(
            raw: &str,
            table: &'a Table,
            table_span: Option<std::ops::Range<usize>>,
            key: &str,
        ) -> Result<$type_, ParseError> {
            let item = get_item(raw, table, table_span.as_ref(), key)?;
            let item_span = item.span();
            item.$getter()
                .ok_or_else(|| {
                    let location = item_span
                        .as_ref()
                        .map(|item_span| resolve_span(raw, item_span))
                        .flatten();
                    ParseError {
                        line: location.map(|l| l.0).unwrap_or(1),
                        column: location.map(|l| l.1).unwrap_or(1),
                        message: format!("item \"{key}\" has wrong data type"),
                        _kind: Default::default(),
                    }
                })
                .map(|v| $mapper(raw, item, v))?
        }
        #[allow(dead_code)]
        fn $opt_fn_name<'a>(
            raw: &str,
            table: &'a Table,
            table_span: Option<std::ops::Range<usize>>,
            key: &str,
        ) -> Result<Option<$type_>, ParseError> {
            Ok(match get_item(raw, table, table_span.as_ref(), key) {
                Ok(item) => {
                    let item_span = item.span();
                    Some(
                        item.$getter()
                            .ok_or_else(|| {
                                let location = item_span
                                    .as_ref()
                                    .map(|item_span| resolve_span(raw, item_span))
                                    .flatten();
                                ParseError {
                                    line: location.map(|l| l.0).unwrap_or(1),
                                    column: location.map(|l| l.1).unwrap_or(1),
                                    message: format!("item \"{key}\" has wrong data type"),
                                    _kind: Default::default(),
                                }
                            })
                            .map(|v| $mapper(raw, item, v))??,
                    )
                }
                Err(_) => None,
            })
        }
    };
}
get_as_type_generator!(
    get_as_string,
    get_as_opt_string,
    String,
    as_str,
    |_: &str, _: &toml_edit::Item, s: &str| { Ok(s.to_string()) }
);
get_as_type_generator!(
    get_as_integer,
    get_as_opt_integer,
    i64,
    as_integer,
    |_: &str, _: &toml_edit::Item, i| { Ok(i64::from(i)) }
);
get_as_type_generator!(
    get_as_unsigned_integer,
    get_as_opt_unsigned_integer,
    u64,
    as_integer,
    |raw: &str, item: &toml_edit::Item, i| {
        if i < 0 {
            let location = item.span().map(|span| resolve_span(raw, &span)).flatten();
            Err(ParseError {
                line: location.map(|l| l.0).unwrap_or(1),
                column: location.map(|l| l.1).unwrap_or(1),
                message: format!("expected non-negative integer value"),
                _kind: Default::default(),
            })
        } else {
            Ok(i64::from(i) as u64)
        }
    }
);
// get_as_type_generator!(
//     get_as_decimal,
//     get_as_opt_decimal,
//     Decimal,
//     as_number,
//     |raw: &str, item: &toml_edit::Item, f: f64| {
//         Decimal::from_f64(f).ok_or_else(|| {
//             anyhow!(file.format_message(item.span(), "can not convert float to decimal"))
//         })
//     }
// );
get_as_type_generator!(
    get_as_bool,
    get_as_opt_bool,
    bool,
    as_bool,
    |_: &str, _: &toml_edit::Item, b| { Ok(b) }
);
get_as_type_generator!(
    get_as_log_level,
    get_as_opt_log_level,
    LevelFilter,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        if s == "info" {
            Ok(LevelFilter::Info)
        }
        // TODO: implement more
        else {
            Err(ParseError::new(
                raw,
                item.span(),
                format!("invalid value for logging level, possible values: TODO"),
            ))
        }
    }
);
/// flat version of [DeviceManagedByChoice]
///
/// used as an intermediate result during parsing
pub enum FlatDeviceManagedByChoice {
    Rosenpass,
    Wireguard,
}
get_as_type_generator!(
    get_as_flat_device_managed_by_choice,
    get_as_opt_flat_device_managed_by_choice,
    FlatDeviceManagedByChoice,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        if s == "rosenpass" {
            Ok(FlatDeviceManagedByChoice::Rosenpass)
        } else if s == "wireguard" {
            Ok(FlatDeviceManagedByChoice::Wireguard)
        } else {
            Err(ParseError::new(
                raw,
                item.span(),
                format!(
                    "invalid value for device's managed-by, possible values are \"rosenpass\" or \"wireguard\""
                ),
            ))
        }
    }
);
get_as_type_generator!(
    get_as_crypto_algorithm_choice,
    get_as_opt_crypto_algorithm_choice,
    CryptoAlgorithmsChoice,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| -> Result<CryptoAlgorithmsChoice, ParseError> {
        unimplemented!()
    }
);

mod sealed {
    pub trait Sealed {}
}
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseIssueLevel {
    Error,
    Warning,
}
pub trait ParseIssueKind: sealed::Sealed + Debug {
    const LEVEL: ParseIssueLevel;
}
#[derive(Debug)]
pub struct Warning;
#[derive(Debug)]
pub struct Error;
impl sealed::Sealed for Warning {}
impl sealed::Sealed for Error {}
impl ParseIssueKind for Warning {
    const LEVEL: ParseIssueLevel = ParseIssueLevel::Warning;
}
impl ParseIssueKind for Error {
    const LEVEL: ParseIssueLevel = ParseIssueLevel::Error;
}
#[derive(Debug)]
pub struct ParseIssueInner<K: ParseIssueKind> {
    line: usize,
    column: usize,
    message: String,
    _kind: PhantomData<K>,
}
impl<K: ParseIssueKind> ParseIssueInner<K> {
    pub fn level(&self) -> ParseIssueLevel {
        K::LEVEL
    }
    pub fn new(
        raw: &str,
        span: Option<std::ops::Range<usize>>,
        message: String,
    ) -> ParseIssueInner<K> {
        let location = span.map(|span| resolve_span(raw, &span)).flatten();
        ParseIssueInner::<K> {
            line: location.map(|l| l.0).unwrap_or(1),
            column: location.map(|l| l.1).unwrap_or(1),
            message: message,
            _kind: Default::default(),
        }
    }
}
impl<K: ParseIssueKind> std::fmt::Display for ParseIssueInner<K> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.level() {
            ParseIssueLevel::Warning => {
                write!(f, "warning:{}:{}: {}", self.line, self.column, self.message)
            }
            ParseIssueLevel::Error => {
                write!(f, "error:{}:{}: {}", self.line, self.column, self.message)
            }
        }
    }
}
impl<K: ParseIssueKind> std::error::Error for ParseIssueInner<K> {}
pub type ParseWarning = ParseIssueInner<Warning>;
pub type ParseError = ParseIssueInner<Error>;
#[derive(Debug)]
pub enum ParseIssue {
    Warning(ParseWarning),
    Error(ParseError),
}
impl ParseIssue {
    pub fn line(&self) -> usize {
        match &self {
            ParseIssue::Warning(inner) => inner.line,
            ParseIssue::Error(inner) => inner.line,
        }
    }
    pub fn column(&self) -> usize {
        match &self {
            ParseIssue::Warning(inner) => inner.column,
            ParseIssue::Error(inner) => inner.column,
        }
    }
    pub fn message(&self) -> &str {
        match &self {
            ParseIssue::Warning(inner) => inner.message.as_str(),
            ParseIssue::Error(inner) => inner.message.as_str(),
        }
    }
    // TODO: fn is_error()
    // TODO: fn is_warning()
}
impl std::fmt::Display for ParseIssue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // let line = self.line();
        // let column = self.column();
        // let message = self.message();
        // match &self {
        //     Self::Warning(inner) => write!(f, "warning:{}:{}: {}", line, column, message),
        //     Self::Error(inner) => write!(f, "error:{}:{}: {}", line, column, message),
        // }
        match &self {
            Self::Warning(inner) => write!(f, "{}", inner),
            Self::Error(inner) => write!(f, "{}", inner),
        }
    }
}
impl std::error::Error for ParseIssue {}

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
