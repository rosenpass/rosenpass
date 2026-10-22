use super::errors::ParseError;
use crate::{
    config::{KeyFromDisk, PresharedKeySource},
    oldconfig::RosenpassPeerOskDomainSeparator,
    protocol::ProtocolVersion,
};
use log::LevelFilter;
use std::str::FromStr;
use tokio::sync::broadcast::error::RecvError::Lagged;
use toml_edit::InlineTable;
/// an be used on the output of `get_as_*()` if `let mut errors: Parse<Error> = Vec::new();` has been defined
macro_rules! process_result {
    ($errors: expr, $result: expr) => {
        $result.map(|v| Some(v)).unwrap_or_else(|err| {
            $errors.extend_from_slice(&err);
            None
        })
    };
}
pub(crate) use process_result;
/// converts a span from `toml_edit` into a line number and column number
pub(crate) fn resolve_span(raw: &str, span: &std::ops::Range<usize>) -> Option<(usize, usize)> {
    let foo = raw.get(0..span.start)?.split("\n").collect::<Vec<_>>();
    Some((foo.len(), foo.last().unwrap().len() + 1))
}
/// gets the value in `table` associated with `key` or returns an [`Err`] if the key does not exist within the table
///
/// - `file` is a reference to the file holding the `table` and is only required to format the error message in case of a missing key
/// - `table_span` is the location of the `table` within the TOML `file` and is only required to format the error message in case of a missing key
fn get_item<'a, T: toml_edit::TableLike>(
    raw: &str,
    table: &'a T,
    table_span: Option<&std::ops::Range<usize>>,
    key: &str,
) -> Result<&'a toml_edit::Item, ParseError> {
    table.get(key).ok_or_else(|| {
        ParseError::new(
            raw,
            table_span.map(|span| span.clone()),
            format!("require key \"{key}\""),
        )
    })
}
macro_rules! getter_to_typename {
    (as_str) => {
        "string"
    };
    (as_integer) => {
        "integer"
    };
    (as_bool) => {
        "boolean"
    };
    (as_array) => {
        "array"
    };
    (as_inline_table) => {
        "inline table"
    };
    ($getter: ident) => {
        compile_error!(concat!("unexpected getter: ", stringify!($getter)))
    };
}

macro_rules! get_as_type_generator {
    ($fn_name: ident,$opt_fn_name: ident, $type_: ty, $getter: ident, $mapper: expr) => {
        #[allow(dead_code)]
        pub fn $fn_name<'a, T: toml_edit::TableLike>(
            raw: &'a str,
            table: &'a T,
            table_span: Option<std::ops::Range<usize>>,
            key: &str,
        ) -> Result<$type_, Vec<ParseError>> {
            let item = get_item(raw, table, table_span.as_ref(), key).map_err(|err| vec![err])?;
            let item_span = item.span();
            item.$getter()
                .ok_or_else(|| {
                    vec![ParseError::new(
                        raw,
                        item_span,
                        format!(
                            "item \"{key}\" has wrong data type, expected {}",
                            getter_to_typename!($getter)
                        ),
                    )]
                })
                .map(|v| $mapper(raw, item, v))?
        }
        #[allow(dead_code)]
        pub fn $opt_fn_name<'a, T: toml_edit::TableLike>(
            raw: &'a str,
            table: &'a T,
            table_span: Option<std::ops::Range<usize>>,
            key: &str,
        ) -> Result<Option<$type_>, Vec<ParseError>> {
            match get_item(raw, table, table_span.as_ref(), key) {
                Ok(item) => {
                    let item_span = item.span();
                    Ok(Some(
                        item.$getter()
                            .ok_or_else(|| {
                                vec![ParseError::new(
                                    raw,
                                    item_span,
                                    format!(
                                        "item \"{key}\" has wrong data type, expected {}",
                                        getter_to_typename!($getter)
                                    ),
                                )]
                            })
                            .map(|v| $mapper(raw, item, v))??,
                    ))
                }
                Err(_) => Ok(None),
            }
        }
    };
}
get_as_type_generator!(
    get_as_string,
    get_as_opt_string,
    String,
    as_str,
    |_: &str, _: &toml_edit::Item, s: &str| -> Result<_, Vec<ParseError>> { Ok(s.to_string()) }
);
get_as_type_generator!(
    get_as_integer,
    get_as_opt_integer,
    i64,
    as_integer,
    |_: &str, _: &toml_edit::Item, i| -> Result<_, Vec<ParseError>> { Ok(i64::from(i)) }
);
get_as_type_generator!(
    get_as_unsigned_integer,
    get_as_opt_unsigned_integer,
    u64,
    as_integer,
    |raw: &str, item: &toml_edit::Item, i| {
        if i < u64::MIN as _ {
            Err(vec![ParseError::new(
                raw,
                item.span(),
                format!("expected non-negative integer value"),
            )])
        } else {
            Ok(i64::from(i) as u64)
        }
    }
);
get_as_type_generator!(
    get_as_u16,
    get_as_opt_u16,
    u16,
    as_integer,
    |raw: &str, item: &toml_edit::Item, i| {
        let mut errors = Vec::new();
        if i < u16::MIN as _ {
            errors.push(ParseError::new(
                raw,
                item.span(),
                format!("expected non-negative integer value"),
            ));
        }
        if i > u16::MAX as _ {
            errors.push(ParseError::new(
                raw,
                item.span(),
                format!("expected integer value not larger than {}", u16::MAX),
            ));
        }
        if errors.is_empty() {
            Ok(u16::try_from(i).expect("unreachable") as u16)
        } else {
            Err(errors)
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
    |_: &str, _: &toml_edit::Item, b| -> Result<_, Vec<ParseError>> { Ok(b) }
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
            Err(vec![ParseError::new(
                raw,
                item.span(),
                format!("invalid value for logging level, possible values: TODO"),
            )])
        }
    }
);
get_as_type_generator!(
    get_as_path_buf,
    get_as_opt_path_buf,
    std::path::PathBuf,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        std::path::PathBuf::from_str(s)
            .map_err(|err| vec![ParseError::new(raw, item.span(), err.to_string())])
    }
);
get_as_type_generator!(
    get_as_array,
    get_as_opt_array,
    &'a toml_edit::Array,
    as_array,
    |_, _, list: &'a toml_edit::Array| -> Result<_, Vec<ParseError>> { Ok(list) }
);
get_as_type_generator!(
    get_as_inline_table,
    get_as_opt_inline_table,
    &'a toml_edit::InlineTable,
    as_inline_table,
    |_, _, tab: &'a toml_edit::InlineTable| -> Result<_, Vec<ParseError>> { Ok(tab) }
);
get_as_type_generator!(
    get_as_vec_string,
    get_as_opt_vec_string,
    Vec<String>,
    as_array,
    |raw: &'a str, item: &'a toml_edit::Item, array: &'a toml_edit::Array| {
        let array = array
            .iter()
            .map(|item| -> Result<String, ParseError> {
                item.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    ParseError::new(raw, item.span(), "expected array of strings".to_string())
                })
            })
            .collect::<Vec<_>>();

        if array.iter().find(|x| x.is_err()).is_some() {
            Err(array
                .into_iter()
                .filter_map(|x| x.err())
                .collect::<Vec<_>>())
        } else {
            Ok(array
                .into_iter()
                .map(|x| x.expect("unreachable"))
                .collect::<Vec<_>>())
        }
    }
);
get_as_type_generator!(
    get_as_protocol_version,
    get_as_opt_protocol_version,
    ProtocolVersion,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        // TODO: properly deserialize this
        if s.to_lowercase() == "v02" {
            Ok(ProtocolVersion::V02)
        } else if s.to_lowercase() == "v03" {
            Ok(ProtocolVersion::V03)
        } else {
            // TODO: proper list of supported values
            Err(vec![ParseError::new(
                raw,
                item.span(),
                format!("invalid protocol version, supported values: v02, v03"),
            )])
        }
    }
);
get_as_type_generator!(
    get_as_socket_addr,
    get_as_opt_socket_addr,
    std::net::SocketAddr,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        std::net::SocketAddr::from_str(s)
            .map_err(|err| vec![ParseError::new(raw, item.span(), err.to_string())])
    }
);

get_as_type_generator!(
    get_as_osk_domain_separator,
    get_as_opt_osk_domain_separator,
    RosenpassPeerOskDomainSeparator,
    as_inline_table,
    |raw: &str, item: &toml_edit::Item, inline_table: &InlineTable| {
        let mut errors = Vec::new();
        const ORG: &str = "organization";
        const LABELS: &str = "labels";

        // read "organization"
        let organization = process_result!(
            errors,
            get_as_string(raw, inline_table, inline_table.span(), ORG)
        );

        // read "labels"
        let osk_labels = process_result!(
            errors,
            get_as_vec_string(raw, inline_table, inline_table.span(), LABELS)
        );

        deny_illegal_keys(raw, inline_table, vec![ORG, LABELS]);

        // return
        errors
            .is_empty()
            .then(|| {
                Ok(RosenpassPeerOskDomainSeparator {
                    osk_organization: organization,
                    osk_label: osk_labels,
                })
            })
            .unwrap_or_else(|| Err(errors))
    }
);

pub(crate) fn get_legacy_osk_domain_separator<T: toml_edit::TableLike>(
    raw: &str,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
) -> Result<RosenpassPeerOskDomainSeparator, Vec<ParseError>> {
    let mut errors = Vec::new();
    const LEGACY_ORG: &str = "osk_organization";
    const LEGACY_LABELS: &str = "osk_label";
    const TABLE: &str = "osk-domain-separator";

    let legacy_org = process_result!(
        errors,
        get_as_opt_string(raw, table, table_span.clone(), LEGACY_ORG)
    )
    .flatten();

    let legacy_labels = process_result!(
        errors,
        get_as_opt_vec_string(raw, table, table_span.clone(), LEGACY_LABELS)
    )
    .flatten();

    let osk_table = process_result!(
        errors,
        get_as_opt_inline_table(raw, table, table_span.clone(), TABLE)
    )
    .flatten();

    let osk_domain_separator = match (legacy_org, legacy_labels, osk_table) {
        // none specified
        (None, None, None) => Some(RosenpassPeerOskDomainSeparator {
            osk_organization: None,
            osk_label: None,
        }),
        // legacy specified
        (Some(org), Some(labels), None) => Some(RosenpassPeerOskDomainSeparator {
            osk_organization: Some(org),
            osk_label: Some(labels),
        }),
        // partial legacy option
        (Some(_), None, None) => {
            errors.push(ParseError::new(
                raw,
                table_span.clone(),
                format!(
                    "expected key \"{LEGACY_LABELS}\" because you also specified \"{LEGACY_ORG}\""
                ),
            ));
            None
        }
        (None, Some(_), None) => {
            errors.push(ParseError::new(
                raw,
                table_span.clone(),
                format!(
                    "expected key \"{LEGACY_ORG}\" because you also specified \"{LEGACY_LABELS}\""
                ),
            ));
            None
        }
        // exclusive options
        (Some(_), None, Some(_)) => {
            errors.push(ParseError::new(raw, table_span.clone(),
                format!("keys \"{LEGACY_ORG}\" and \"{TABLE}\" exclude each other and \"{LEGACY_ORG}\" is deprecated"))
            );
            None
        }
        (None, Some(_), Some(_)) => {
            errors.push(ParseError::new(raw, table_span.clone(),
                format!("keys \"{LEGACY_LABELS}\" and \"{TABLE}\" exclude each other and \"{LEGACY_LABELS}\" is deprecated"))
            );
            None
        }
        (Some(_), Some(_), Some(_)) => {
            errors.push(ParseError::new(raw, table_span.clone(),
                format!("keys \"{LEGACY_ORG}\" and \"{LEGACY_LABELS}\" (deprecated OSK definition) can not be used together with \"{TABLE}\""))
            );
            None
        }
        // new specified
        (None, None, Some(osk_table)) => {
            const ORG: &str = "organization";
            const LABELS: &str = "labels";
            let org = process_result!(errors, get_as_string(raw, osk_table, osk_table.span(), ORG));
            let labels = process_result!(
                errors,
                get_as_vec_string(raw, osk_table, osk_table.span(), LABELS)
            );
            process_result!(errors, deny_illegal_keys(raw, osk_table, vec![ORG, LABELS]));
            match (org, labels) {
                (Some(org), Some(labels)) => Some(RosenpassPeerOskDomainSeparator {
                    osk_organization: Some(org),
                    osk_label: Some(labels),
                }),
                _ => None, // errors are already saved by above calls to `process_result`
            }
        }
    };

    // return
    if errors.is_empty() {
        Ok(osk_domain_separator.expect("unreachable"))
    } else {
        Err(errors)
    }
}

get_as_type_generator!(
    get_as_psk_source,
    get_as_opt_psk_source,
    PresharedKeySource,
    as_inline_table,
    |raw: &str, item: &toml_edit::Item, inline_table: &InlineTable| {
        const FILE: &str = "file";
        const DIR: &str = "directory";
        let mut errors = Vec::new();

        let file = process_result!(
            errors,
            get_as_opt_path_buf(raw, inline_table, inline_table.span(), "file")
        )
        .flatten();
        let dir = process_result!(
            errors,
            get_as_opt_path_buf(raw, inline_table, inline_table.span(), "directory")
        )
        .flatten();

        // check that `inline_table` has no further keys (e.g. no plaintext PSK)
        process_result!(
            errors,
            deny_illegal_keys(raw, inline_table, vec![FILE, DIR])
        );

        let psk_source = match (file, dir) {
            (None, None) => {
                errors.push(ParseError::new(
                    raw,
                    inline_table.span(),
                    format!("expected key \"{FILE}\" or \"{DIR}\""),
                ));
                None
            }
            (Some(_), Some(_)) => {
                errors.push(ParseError::new(
                    raw,
                    inline_table.span(),
                    format!("keys \"{FILE}\" and \"{DIR}\" exclude each other"),
                ));
                None
            }
            (Some(file), None) => Some(PresharedKeySource::ReadFromFile(file)),
            (None, Some(dir)) => Some(PresharedKeySource::ReadFromDirectory(dir)),
        };

        if errors.is_empty() {
            Ok(psk_source.expect("unreachable"))
        } else {
            Err(errors)
        }
    }
);

// get_as_type_generator!(
//     get_as_public_key_from_disk,
//     get_as_opt_public_key_from_disk,
//     KeyFromDisk,
//     |raw: &str, item: &toml_edit::Item, inline_table: &InlineTable| {
//         let mut errors = Vec::new();
//         inline_
//     }
// );

// // secret key
// process_result!(
//     errors,
//     get_as_path_buf(raw, inline_table, inline_table.span(), "secret-key-file")
// );
// // public key file
// // public key directory
// // public key

pub(crate) fn deny_illegal_keys<T: toml_edit::TableLike>(
    raw: &str,
    table: &T,
    allowed_keys: Vec<&str>,
) -> Result<(), Vec<ParseError>> {
    let mut errors = Vec::new();
    let illegal_keys = table
        .iter()
        .filter_map(|(key, value)| {
            if allowed_keys.iter().find(|k| **k == key).is_none() {
                Some((key, value.span()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for illegal_key in illegal_keys.iter() {
        errors.push(ParseError::new(
            raw,
            illegal_key.1.clone(),
            format!("illegal key {}", illegal_key.0),
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}
