use super::errors::ParseError;
#[cfg(feature = "experiment_api")]
use crate::config::ApiConfig;
use crate::{
    config::{
        DeviceWireguardOptions, HasInnerType, KeyFromDisk, KeyFromDiskInner,
        KeyFromDiskOrB64EncodedString, KeyFromDiskOrB64EncodedStringInner, Keypair, NewFromInner,
        OurWireguardKeypair, OutputToFileConfig, PeerWireguardOptions, PresharedKeySource,
        TomlConfigFileVersion, WireguardConfig,
    },
    oldconfig::{RosenpassPeerOskDomainSeparator, Verbosity},
    protocol::{ProtocolVersion, osk_domain_separator},
};
use cidr::IpCidr;
use log::LevelFilter;
use ml_kem::Key;
use serde::{Deserialize, de::value::StrDeserializer};
use std::{
    collections::HashSet,
    fmt::Display,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};
use toml_edit::{ArrayOfTables, InlineTable};
use tstr::IsTStr;

// ============================== process parse results ==============================
pub(crate) trait ProcessParseResult {
    type Output;
    fn process_parse_result(self, error_list: &mut Vec<ParseError>) -> Option<Self::Output>;
}
impl<T> ProcessParseResult for Result<T, Vec<ParseError>> {
    type Output = T;
    fn process_parse_result(self, error_list: &mut Vec<ParseError>) -> Option<Self::Output> {
        self.map(|v| Some(v)).unwrap_or_else(|err| {
            error_list.extend_from_slice(&err);
            None
        })
    }
}
impl<T> ProcessParseResult for Result<T, ParseError> {
    type Output = T;
    fn process_parse_result(self, error_list: &mut Vec<ParseError>) -> Option<Self::Output> {
        self.map(|v| Some(v)).unwrap_or_else(|err| {
            error_list.push(err);
            None
        })
    }
}
impl<T> ProcessParseResult for Vec<Result<T, Vec<ParseError>>> {
    type Output = Vec<T>;
    fn process_parse_result(self, error_list: &mut Vec<ParseError>) -> Option<Self::Output> {
        let errors = self
            .iter()
            .filter_map(|x| x.as_ref().err())
            .flatten()
            .cloned()
            .collect::<Vec<ParseError>>();
        error_list.extend_from_slice(&errors);
        if errors.is_empty() {
            Some(self.into_iter().map(|x| x.expect("unreachable")).collect())
        } else {
            None
        }
    }
}
impl<T> ProcessParseResult for Vec<Result<T, ParseError>> {
    type Output = Vec<T>;
    fn process_parse_result(self, error_list: &mut Vec<ParseError>) -> Option<Self::Output> {
        let errors = self
            .iter()
            .filter_map(|x| x.as_ref().err())
            .cloned()
            .collect::<Vec<ParseError>>();
        error_list.extend_from_slice(&errors);
        if errors.is_empty() {
            Some(self.into_iter().map(|x| x.expect("unreachable")).collect())
        } else {
            None
        }
    }
}
mod sealed {
    pub trait Sealed {}
    // This is only implemented for `Option<T>` and not for `Result<T,E>` to make sure that the
    // caller has called `process_parse_result` before calling `guaranteed_unwrap`.
    impl<T> Sealed for Option<T> {}
}
pub(crate) trait GuaranteedUnwrap: sealed::Sealed {
    type Output;
    fn guaranteed_unwrap(self) -> Self::Output;
}
impl<T> GuaranteedUnwrap for Option<T> {
    type Output = T;
    fn guaranteed_unwrap(self) -> Self::Output {
        self.expect(
            "The code panicked because its execution took a path that \
            the developers expected to be unreachable. This is a bug. \
            It would be kind if you could open a bug report on \
            https://github.com/rosenpass/rosenpass/issues",
        )
    }
}
// ============================== general parsing helpers ==============================
pub(crate) fn deny_illegal_keys<T: toml_edit::TableLike + ?Sized>(
    raw: &str,
    file_path: &Path,
    table: &T,
    allowed_keys: Vec<&str>,
) -> Result<(), Vec<ParseError>> {
    let mut errors = Vec::new();
    let illegal_keys = table
        .iter()
        .filter_map(|(key, value)| {
            if allowed_keys.iter().find(|k| **k == key).is_none() {
                Some((key, table.key(key).unwrap().span()))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    for illegal_key in illegal_keys.iter() {
        errors.push(ParseError::new_ext(
            raw,
            file_path,
            illegal_key.1.clone(),
            format!("illegal key \"{}\"", illegal_key.0),
            "illegal key occurs here",
        ));
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

/// converts a span from `toml_edit` into a line number and column number
pub(crate) fn resolve_span(raw: &str, span: &std::ops::Range<usize>) -> Option<(usize, usize)> {
    let lines = raw.get(0..span.start)?.split("\n").collect::<Vec<_>>();
    Some((lines.len(), lines.last().unwrap().len() + 1))
}
pub(crate) fn combine_spans(
    span1: &std::ops::Range<usize>,
    span2: &std::ops::Range<usize>,
) -> std::ops::Range<usize> {
    span1.start..span2.end
}
pub(crate) fn combine_opt_spans(
    span1: Option<std::ops::Range<usize>>,
    span2: Option<std::ops::Range<usize>>,
) -> Option<std::ops::Range<usize>> {
    match (span1, span2) {
        (None, None) => None,
        (Some(span), None) => Some(span.clone()),
        (None, Some(span)) => Some(span.clone()),
        (Some(span1), Some(span2)) => Some(combine_spans(&span1, &span2)),
    }
}
pub trait GetKeyValueSpan {
    fn get_key_value_span(&self, key: &str) -> Option<std::ops::Range<usize>>;
    fn get_key_span(&self, key: &str) -> Option<std::ops::Range<usize>>;
}
impl<T: toml_edit::TableLike> GetKeyValueSpan for T {
    fn get_key_value_span(&self, key: &str) -> Option<std::ops::Range<usize>> {
        self.get_key_value(key)
            .and_then(|(k, v)| combine_opt_spans(k.span(), v.span()))
    }
    fn get_key_span(&self, key: &str) -> Option<std::ops::Range<usize>> {
        self.key(key).and_then(|k| k.span())
    }
}

/// gets the value in `table` associated with `key` or returns an [`Err`] if the key does not exist within the table
///
/// - `file` is a reference to the file holding the `table` and is only required to format the error message in case of a missing key
/// - `table_span` is the location of the `table` within the TOML `file` and is only required to format the error message in case of a missing key
fn get_item<'a, T: toml_edit::TableLike + ?Sized>(
    raw: &str,
    file_path: &Path,
    table: &'a T,
    table_span: Option<&std::ops::Range<usize>>,
    key: &str,
) -> Result<&'a toml_edit::Item, ParseError> {
    table.get(key).ok_or_else(|| {
        ParseError::new(
            raw,
            file_path,
            table_span.cloned(),
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
    (as_table_like) => {
        "table or inline table"
    };
    ($getter: ident) => {
        compile_error!(concat!("unexpected getter: ", stringify!($getter)))
    };
}

// ============================== get_as_<T> functions ==============================

macro_rules! get_as_type_generator {
    ($fn_name: ident, $opt_fn_name: ident, [$($generics:tt)*], $type_: ty, $getter: ident, $mapper: expr) => {
        #[allow(dead_code)]
        pub fn $fn_name<'a, TableLike: toml_edit::TableLike + ?Sized, $($generics)*>(
            raw: &'a str,
            file_path: &Path,
            table: &'a TableLike,
            table_span: Option<std::ops::Range<usize>>,
            key: &str,
        ) -> Result<$type_, Vec<ParseError>> {
            let item = get_item(raw, file_path, table, table_span.as_ref(), key).map_err(|err| vec![err])?;
            let item_span = item.span();
            item.$getter()
                .ok_or_else(|| {
                    vec![ParseError::new(
                        raw,
                        file_path,
                        item_span,
                        format!(
                            "item \"{key}\" has wrong data type, expected {}",
                            getter_to_typename!($getter)
                        ),
                    )]
                })
                .map(|v| $mapper(raw, file_path, item, v))?
        }
        #[allow(dead_code)]
        pub fn $opt_fn_name<'a, TableLike: toml_edit::TableLike + ?Sized, $($generics)*>(
            raw: &'a str,
            file_path: &Path,
            table: &'a TableLike,
            table_span: Option<std::ops::Range<usize>>,
            key: &str,
        ) -> Result<Option<$type_>, Vec<ParseError>> {
            match get_item(raw, file_path, table, table_span.as_ref(), key) {
                Ok(item) => {
                    let item_span = item.span();
                    Ok(Some(
                        item.$getter()
                            .ok_or_else(|| {
                                vec![ParseError::new(
                                    raw,
                                    file_path,
                                    item_span,
                                    format!(
                                        "item \"{key}\" has wrong data type, expected {}",
                                        getter_to_typename!($getter)
                                    ),
                                )]
                            })
                            .map(|v| $mapper(raw, file_path, item, v))??,
                    ))
                }
                Err(_) => Ok(None),
            }
        }
    };
}

// String
get_as_type_generator!(
    get_as_string,
    get_as_opt_string,
    [],
    String,
    as_str,
    |_raw: &str,
     _file_path: &Path,
     _item: &toml_edit::Item,
     s: &str|
     -> Result<_, Vec<ParseError>> { Ok(s.to_string()) }
);

fn i64_to_int<T: num_traits::PrimInt + Display>(
    raw: &str,
    file_path: &Path,
    span: Option<std::ops::Range<usize>>,
    value: i64,
) -> Result<T, Vec<ParseError>> {
    if i128::from(value)
        < T::min_value()
            .to_i128()
            .expect("can not transform integer to i128")
    {
        Err(vec![ParseError::new(
            raw,
            file_path,
            span,
            format!("value out of bounds (minimum is {})", T::min_value()),
        )])
    } else if i128::from(value)
        > T::max_value()
            .to_i128()
            .expect("can not transform integer to i128")
    {
        Err(vec![ParseError::new(
            raw,
            file_path,
            span,
            format!("value out of bounds (maximum is {})", T::max_value()),
        )])
    } else {
        Ok(T::from(value).expect("can not transform integer"))
    }
}

// i64
get_as_type_generator!(
    get_as_integer,
    get_as_opt_integer,
    [],
    i64,
    as_integer,
    |_: &str, _: &Path, _: &toml_edit::Item, i| -> Result<_, Vec<ParseError>> { Ok(i) }
);

// u64
get_as_type_generator!(
    get_as_unsigned_integer,
    get_as_opt_unsigned_integer,
    [],
    u64,
    as_integer,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, i| {
        i64_to_int(raw, file_path, item.span(), i)
    }
);

// Vec<i32>
get_as_type_generator!(
    get_as_vec_i32,
    get_as_opt_vec_i32,
    [],
    Vec<i32>,
    as_array,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, array: &toml_edit::Array| {
        let mut errors = Vec::new();
        let array = array
            .iter()
            .map(|item| match item.as_integer() {
                Some(integer) => Ok((integer, item.span())),
                None => Err(ParseError::new(
                    raw,
                    file_path,
                    item.span(),
                    format!(
                        "item has wrong data type, expected {}",
                        getter_to_typename!(as_integer)
                    ),
                )),
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }
        let array = array
            .unwrap()
            .iter()
            .map(|(integer, span)| i64_to_int(raw, file_path, span.clone(), *integer))
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(array.expect("unreachable"))
    }
);

// u16
get_as_type_generator!(
    get_as_u16,
    get_as_opt_u16,
    [],
    u16,
    as_integer,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, i| {
        i64_to_int(raw, file_path, item.span(), i)
    }
);

// bool
get_as_type_generator!(
    get_as_bool,
    get_as_opt_bool,
    [],
    bool,
    as_bool,
    |_raw: &str, _file_path: &Path, _item: &toml_edit::Item, b| -> Result<_, Vec<ParseError>> {
        Ok(b)
    }
);

// log::LevelFilter
get_as_type_generator!(
    get_as_log_level,
    get_as_opt_log_level,
    [],
    LevelFilter,
    as_str,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, s: &str| {
        todo!();
        // TODO: implement more variants or use serde_plain

        const INFO: &str = "info";
        if s == INFO {
            Ok(LevelFilter::Info)
        } else {
            Err(vec![ParseError::new(
                raw,
                file_path,
                item.span(),
                format!("invalid value for logging level, possible values: \"{INFO}\""),
            )])
        }
    }
);

// config::Verbosity
get_as_type_generator!(
    get_as_verbosity_level,
    get_as_opt_verbosity_level,
    [],
    Verbosity,
    as_str,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, s: &str| {
        Verbosity::deserialize(StrDeserializer::<serde::de::value::Error>::new(s)).map_err(|err| {
            vec![ParseError::new(
                raw,
                file_path,
                item.span(),
                format!("{err}"),
            )]
        })
    }
);

// PathBuf
get_as_type_generator!(
    get_as_path_buf,
    get_as_opt_path_buf,
    [],
    PathBuf,
    as_str,
    |_raw: &str, _: &Path, _item: &toml_edit::Item, s: &str| -> Result<_, Vec<ParseError>> {
        Ok(PathBuf::from(s))
    }
);

// Vec<PathBuf>
get_as_type_generator!(
    get_as_vec_path_buf,
    get_as_opt_vec_path_buf,
    [],
    Vec<PathBuf>,
    as_array,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, array: &toml_edit::Array| {
        let mut errors = Vec::new();
        let array = array
            .iter()
            .map(|x| {
                x.as_str().ok_or_else(|| {
                    ParseError::new(
                        raw,
                        file_path,
                        x.span(),
                        format!(
                            "item has wrong data type, expected {}",
                            getter_to_typename!(as_str)
                        ),
                    )
                })
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(array
            .unwrap()
            .into_iter()
            .map(PathBuf::from)
            .collect::<Vec<_>>())
    }
);

// toml_edit::Array
get_as_type_generator!(
    get_as_array,
    get_as_opt_array,
    [],
    &'a toml_edit::Array,
    as_array,
    |_, _: &Path, _, list: &'a toml_edit::Array| -> Result<_, Vec<ParseError>> { Ok(list) }
);

// toml_edit::InlineTable
get_as_type_generator!(
    get_as_inline_table,
    get_as_opt_inline_table,
    [],
    &'a toml_edit::InlineTable,
    as_inline_table,
    |_raw: &str,
     _file_path: &Path,
     _item: &toml_edit::Item,
     tab: &'a toml_edit::InlineTable|
     -> Result<_, Vec<ParseError>> { Ok(tab) }
);

// Vec<String>
get_as_type_generator!(
    get_as_vec_string,
    get_as_opt_vec_string,
    [],
    Vec<String>,
    as_array,
    |raw: &'a str, file_path: &Path, _item: &'a toml_edit::Item, array: &'a toml_edit::Array| {
        let array = array
            .iter()
            .map(|item| -> Result<String, ParseError> {
                item.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    ParseError::new(
                        raw,
                        file_path,
                        item.span(),
                        "expected array of strings".to_string(),
                    )
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

// ProtocolVersion
pub(crate) fn as_protocol_version(
    raw: &str,
    file_path: &Path,
    item: &toml_edit::Item,
    serialized: &str,
) -> Result<ProtocolVersion, Vec<ParseError>> {
    const PROTO_2: &str = "2";
    const PROTO_3: &str = "3";
    if serialized == PROTO_2 {
        Ok(ProtocolVersion::V02)
    } else if serialized == PROTO_3 {
        Ok(ProtocolVersion::V03)
    } else {
        Err(vec![ParseError::new(
            raw,
            file_path,
            item.span(),
            format!("invalid protocol version; valid options are \"{PROTO_2}\" or \"{PROTO_3}\""),
        )])
    }
}
get_as_type_generator!(
    get_as_protocol_version,
    get_as_opt_protocol_version,
    [],
    ProtocolVersion,
    as_str,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, s: &str| {
        as_protocol_version(raw, file_path, item, s)
    }
);
get_as_type_generator!(
    get_as_hashset_protocol_version,
    get_as_opt_hashset_protocol_version,
    [],
    HashSet<ProtocolVersion>,
    as_array,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, array: &toml_edit::Array| {
        let mut errors = Vec::new();

        // map to Array of Strings
        let array = array
            .iter()
            .map(|item| -> Result<String, ParseError> {
                item.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    ParseError::new(
                        raw,
                        file_path,
                        item.span(),
                        "expected array of strings".to_string(),
                    )
                })
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }
        let array = array.expect("unreachable");

        // map to Array of ProtocolVersion
        let array = array
            .iter()
            .map(|x| as_protocol_version(raw, file_path, item, x))
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }
        let array = array.expect("unreachable");

        // make list unique
        let hashset = HashSet::from_iter(array.iter().cloned());
        if hashset.len() != array.len() {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                item.span(),
                "duplicate values in set of protocol versions".to_string(),
            )]);
        }

        // return
        Ok(hashset)
    }
);

// SocketAddr
get_as_type_generator!(
    get_as_socket_addr,
    get_as_opt_socket_addr,
    [],
    SocketAddr,
    as_str,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, s: &str| {
        SocketAddr::from_str(s).map_err(|err| {
            vec![ParseError::new(
                raw,
                file_path,
                item.span(),
                err.to_string(),
            )]
        })
    }
);

// Vec<SocketAddr>
get_as_type_generator!(
    get_as_vec_socket_addr,
    get_as_opt_vec_socket_addr,
    [],
    Vec<SocketAddr>,
    as_array,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, array: &toml_edit::Array| {
        let mut errors = Vec::new();

        // transmute items to strings
        let array = array
            .iter()
            .map(|x| match x.as_str() {
                Some(s) => Ok((s, x.span())),
                None => Err(ParseError::new(
                    raw,
                    file_path,
                    x.span(),
                    format!(
                        "item has wrong data type: expected {}",
                        getter_to_typename!(as_str)
                    ),
                )),
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);

        // return on error
        if !errors.is_empty() {
            return Err(errors);
        }
        let array = array.guaranteed_unwrap();

        // transmute strings to socket addresses
        let array = array
            .iter()
            .map(|(string, span)| {
                SocketAddr::from_str(string).map_err(|err| {
                    vec![ParseError::new(
                        raw,
                        file_path,
                        span.clone(),
                        err.to_string(),
                    )]
                })
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);

        // return
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(array.guaranteed_unwrap())
    }
);

// IpCidr
get_as_type_generator!(
    get_as_ip_cidr,
    get_as_opt_ip_cidr,
    [],
    IpCidr,
    as_str,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, s: &str| {
        IpCidr::from_str(s).map_err(|e| {
            vec![ParseError::new(
                raw,
                file_path,
                item.span(),
                "item \"{}\" has wrong data type, expected network in CIDR notation",
            )]
        })
    }
);
// Vec<IpCidr>
get_as_type_generator!(
    get_as_vec_ip_cidr,
    get_as_opt_vec_ip_cidr,
    [],
    Vec<IpCidr>,
    as_array,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, array: &toml_edit::Array| {
        let mut errors = Vec::new();

        // transmute item to string
        let array = array
            .into_iter()
            .map(|x| match x.as_str() {
                Some(s) => Ok((s, x.span())),
                None => Err(ParseError::new(
                    raw,
                    file_path,
                    x.span(),
                    format!(
                        "item has wrong data type, expected {}",
                        getter_to_typename!(as_str)
                    ),
                )),
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }

        // transmute string to IpCidr
        let array = array
            .guaranteed_unwrap()
            .into_iter()
            .map(|(string, span)| {
                IpCidr::from_str(string).map_err(|e| {
                    ParseError::new(
                        raw,
                        file_path,
                        span,
                        format!("item has wrong data type, expected network in CIDR notation"),
                    )
                })
            })
            .collect::<Vec<_>>()
            .process_parse_result(&mut errors);
        if !errors.is_empty() {
            return Err(errors);
        }

        // return
        Ok(array.guaranteed_unwrap())
    }
);

// OSK Domain Separator
get_as_type_generator!(
    get_as_osk_domain_separator,
    get_as_opt_osk_domain_separator,
    [],
    RosenpassPeerOskDomainSeparator,
    as_inline_table,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, inline_table: &InlineTable| {
        let mut errors = Vec::new();
        const ORG: &str = "organization";
        const LABELS: &str = "labels";

        // read "organization"
        let organization = get_as_string(raw, file_path, inline_table, inline_table.span(), ORG)
            .process_parse_result(&mut errors);

        // read "labels"
        let osk_labels =
            get_as_vec_string(raw, file_path, inline_table, inline_table.span(), LABELS)
                .process_parse_result(&mut errors);

        deny_illegal_keys(raw, file_path, inline_table, vec![ORG, LABELS])
            .process_parse_result(&mut errors);

        // return
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(RosenpassPeerOskDomainSeparator {
            osk_organization: organization,
            osk_label: osk_labels,
        })
    }
);

// OSK Domain Separator (legacy-aware)
pub(crate) fn get_legacy_osk_domain_separator<T: toml_edit::TableLike>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    legacy_org_name: &str,
    legacy_labels_name: &str,
    table_name: &str,
) -> Result<RosenpassPeerOskDomainSeparator, Vec<ParseError>> {
    let mut errors = Vec::new();

    let legacy_org = get_as_opt_string(raw, file_path, table, table_span.clone(), legacy_org_name)
        .process_parse_result(&mut errors)
        .flatten();

    let legacy_labels = get_as_opt_vec_string(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_labels_name,
    )
    .process_parse_result(&mut errors)
    .flatten();

    let osk_table = get_as_opt_inline_table(raw, file_path, table, table_span.clone(), table_name)
        .process_parse_result(&mut errors)
        .flatten();

    if !errors.is_empty() {
        return Err(errors);
    }

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
                file_path,
                table_span.clone(),
                format!(
                    "expected key \"{legacy_labels_name}\" because you also specified \"{legacy_org_name}\""
                ),
            ));
            None
        }
        (None, Some(_), None) => {
            errors.push(ParseError::new(
                raw,
                file_path,
                table_span.clone(),
                format!(
                    "expected key \"{legacy_org_name}\" because you also specified \"{legacy_labels_name}\""
                ),
            ));
            None
        }
        // exclusive options
        (Some(_), None, Some(_)) => {
            errors.push(ParseError::new(raw, file_path,table.get_key_value_span(legacy_org_name),
                format!("keys \"{legacy_org_name}\" and \"{table_name}\" are mutually exclusive and \"{legacy_org_name}\" is deprecated"))
            );
            None
        }
        (None, Some(_), Some(_)) => {
            errors.push(ParseError::new(raw, file_path, table.get_key_value_span(legacy_labels_name),
                format!("keys \"{legacy_labels_name}\" and \"{table_name}\" are mutually exclusive and \"{legacy_labels_name}\" is deprecated"))
            );
            None
        }
        (Some(_), Some(_), Some(_)) => {
            errors.push(ParseError::new(raw, file_path,table_span.clone(),
                format!("keys \"{legacy_org_name}\" and \"{legacy_labels_name}\" (deprecated OSK definition) can not be used together with \"{table_name}\""))
            );
            None
        }
        // new specified
        (None, None, Some(osk_table)) => {
            const ORG: &str = "organization";
            const LABELS: &str = "labels";
            let org = get_as_string(raw, file_path, osk_table, osk_table.span(), ORG)
                .process_parse_result(&mut errors);
            let labels = get_as_vec_string(raw, file_path, osk_table, osk_table.span(), LABELS)
                .process_parse_result(&mut errors);
            deny_illegal_keys(raw, file_path, osk_table, vec![ORG, LABELS])
                .process_parse_result(&mut errors);
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

// PSK Source
get_as_type_generator!(
    get_as_psk_source,
    get_as_opt_psk_source,
    [],
    PresharedKeySource,
    as_inline_table,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, inline_table: &InlineTable| {
        const FILE: &str = "file";
        const DIR: &str = "directory";
        let mut errors = Vec::new();

        let file = get_as_opt_path_buf(raw, file_path, inline_table, inline_table.span(), "file")
            .process_parse_result(&mut errors)
            .flatten();
        let dir = get_as_opt_path_buf(
            raw,
            file_path,
            inline_table,
            inline_table.span(),
            "directory",
        )
        .process_parse_result(&mut errors)
        .flatten();

        // check that `inline_table` has no further keys (e.g. no plaintext PSK)
        deny_illegal_keys(raw, file_path, inline_table, vec![FILE, DIR])
            .process_parse_result(&mut errors);

        let psk_source = match (file, dir) {
            (None, None) => {
                errors.push(ParseError::new(
                    raw,
                    file_path,
                    inline_table.span(),
                    format!("expected key \"{FILE}\" or \"{DIR}\""),
                ));
                None
            }
            (Some(_), Some(_)) => {
                errors.push(ParseError::new(
                    raw,
                    file_path,
                    inline_table.get_key_value_span(FILE),
                    format!("keys \"{FILE}\" and \"{DIR}\" are mutually exclusive"),
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

pub(crate) fn get_legacy_psk_source<T: toml_edit::TableLike>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    legacy_name: &str,
    table_name: &str,
) -> Result<Result<PresharedKeySource, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    let legacy_psk_file =
        get_as_opt_path_buf(raw, file_path, table, table_span.clone(), legacy_name)
            .process_parse_result(&mut errors)
            .flatten();
    let psk_table = get_as_opt_psk_source(raw, file_path, table, table_span.clone(), table_name)
        .process_parse_result(&mut errors)
        .flatten();
    let psk_source: Result<PresharedKeySource, ParseError> = match (legacy_psk_file, psk_table) {
        // duplicate definition
        (Some(_), Some(_)) => {
            let err = ParseError::new(
                raw,
                file_path,
                table_span.clone(),
                format!(
                    "keys \"{l}\" and \"{table_name}\" exclude each other and \"{l}\" is deprecated",
                    l = legacy_name
                ),
            );
            errors.push(err.clone());
            Err(err)
        }
        // no PSK specified
        (None, None) => Err(ParseError::new(
            raw,
            file_path,
            table_span.clone(),
            format!("require key \"{table_name}\""),
        )),
        // legacy PSK
        (Some(legacy_psk_file), None) => Ok(PresharedKeySource::ReadFromFile(legacy_psk_file)),
        // new semantic PSK
        (None, Some(psk_table)) => Ok(psk_table),
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(psk_source)
}

/// reads a key source which can either be a file or a directory ([`KeyFromDisk`])
///
/// returns:
/// - `Ok(Ok(KeyFromDisk))` if the key was successfully read
/// - `Err(Vec<ParseError>)` if errors occured during parsing
/// - `Ok(Err(ParseError))` if the key is not present in the table
pub(crate) fn get_key_from_disk<T: toml_edit::TableLike, FN: IsTStr, const SIZE: usize>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    deny_illegal_keys_check: bool,
    file_key: &str,
    dir_key: &str,
) -> Result<Result<KeyFromDisk<FN, SIZE>, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    let file = get_as_opt_path_buf(raw, file_path, table, table_span.clone(), file_key)
        .process_parse_result(&mut errors)
        .flatten();
    let dir = get_as_opt_path_buf(raw, file_path, table, table_span.clone(), dir_key)
        .process_parse_result(&mut errors)
        .flatten();

    if deny_illegal_keys_check {
        deny_illegal_keys(raw, file_path, table, vec![file_key, dir_key])
            .process_parse_result(&mut errors);
    }

    // return early if an error occured already during TOML parsing
    if !errors.is_empty() {
        return Err(errors);
    }

    let key = match (file, dir) {
        (None, None) => Err(ParseError::new(
            raw,
            file_path,
            table_span.clone(),
            format!("expected either key \"{file_key}\" or \"{dir_key}\""),
        )),
        (Some(_), Some(_)) => {
            let err = ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(file_key),
                format!("keys \"{file_key}\" and \"{dir_key}\" are mutually exclusive"),
            );
            errors.push(err.clone());
            // the err is just a dummy in this line – the function will return Err(errors) anyways
            Err(err)
        }
        (Some(file), None) => Ok(KeyFromDisk::<FN, SIZE>::new(KeyFromDiskInner::File(file))),
        (None, Some(dir)) => Ok(KeyFromDisk::<FN, SIZE>::new(KeyFromDiskInner::Directory(
            dir,
        ))),
    };

    if errors.is_empty() {
        Ok(key)
    } else {
        Err(errors)
    }
}

/// reads a key source which can either be a file or a directory or an inline Base64-encoded string
///  ([`KeyFromDiskOrB64EncodedString`])
///
/// returns:
/// - `Ok(Ok(KeyFromDiskOrB64EncodedString))` if the key was successfully read
/// - `Err(Vec<ParseError>)` if errors occured during parsing
/// - `Ok(Err(ParseError))` if the key is not present in the table
pub(crate) fn get_key_from_disk_or_b64<T: toml_edit::TableLike, FN: IsTStr, const SIZE: usize>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    deny_illegal_keys_check: bool,
    file_key: &str,
    dir_key: &str,
    b64_key: &str,
) -> Result<Result<KeyFromDiskOrB64EncodedString<FN, SIZE>, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    let file = get_as_opt_path_buf(raw, file_path, table, table_span.clone(), file_key)
        .process_parse_result(&mut errors)
        .flatten();
    let dir = get_as_opt_path_buf(raw, file_path, table, table_span.clone(), dir_key)
        .process_parse_result(&mut errors)
        .flatten();
    let b64 = get_as_opt_string(raw, file_path, table, table_span.clone(), b64_key)
        .process_parse_result(&mut errors)
        .flatten();

    if deny_illegal_keys_check {
        deny_illegal_keys(raw, file_path, table, vec![file_key, dir_key, b64_key])
            .process_parse_result(&mut errors);
    }

    // return early if an error occured already during TOML parsing
    if !errors.is_empty() {
        return Err(errors);
    }

    let key = match (file, dir, b64) {
        // none specified
        (None, None, None) => Err(ParseError::new(
            raw,
            file_path,
            table_span.clone(),
            format!("expected either key \"{file_key}\" or \"{dir_key}\""),
        )),
        // conflicting keys
        (Some(_), Some(_), Some(_)) => {
            let err = ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(file_key),
                format!(
                    "keys \"{file_key}\", \"{dir_key}\" and \"{b64_key}\" {}",
                    "are mutually exclusive, please pick only one"
                ),
            );
            errors.push(err.clone());
            // the err is just a dummy in this line – the function will return Err(errors) anyways
            Err(err)
        }
        (Some(_), Some(_), None) => {
            let err = ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(file_key),
                format!("keys \"{file_key}\" and \"{dir_key}\" are mutually exclusive"),
            );
            errors.push(err.clone());
            // the err is just a dummy in this line – the function will return Err(errors) anyways
            Err(err)
        }
        (Some(_), None, Some(_)) => {
            let err = ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(file_key),
                format!("keys \"{file_key}\" and \"{b64_key}\" are mutually exclusive"),
            );
            errors.push(err.clone());
            // the err is just a dummy in this line – the function will return Err(errors) anyways
            Err(err)
        }
        (None, Some(_), Some(_)) => {
            let err = ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(dir_key),
                format!("keys \"{dir_key}\" and \"{b64_key}\" are mutually exclusive"),
            );
            errors.push(err.clone());
            // the err is just a dummy in this line – the function will return Err(errors) anyways
            Err(err)
        }
        // read from file
        (Some(file), None, None) => Ok(KeyFromDiskOrB64EncodedString::<FN, SIZE>::new(
            KeyFromDiskOrB64EncodedStringInner::File(file),
        )),
        // read from directory
        (None, Some(dir), None) => Ok(KeyFromDiskOrB64EncodedString::<FN, SIZE>::new(
            KeyFromDiskOrB64EncodedStringInner::Directory(dir),
        )),
        // read from inline base64-encoded string
        (None, None, Some(b64)) => Ok(KeyFromDiskOrB64EncodedString::<FN, SIZE>::new(
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(b64),
        )),
    };

    if errors.is_empty() {
        Ok(key)
    } else {
        Err(errors)
    }
}

/// reads a public key from disk which can be one of these:
///
/// legacy:
/// ```toml
/// key = "file/to/key/"
/// ```
///
/// new semantic:
/// ```toml
/// key = {
///     public-key-file = "path/to/key",
///     # alternative:
///     # public-key-directory = "path/to/key-dir",
/// }
/// ```
///
/// returns:
/// - `Ok(Ok(KeyFromDisk))` if the key was successfully read
/// - `Err(Vec<ParseError>)` if errors occured during parsing
/// - `Ok(Err(ParseError))` if the key is not present in the table
pub(crate) fn get_legacy_public_key_from_disk<
    T: toml_edit::TableLike,
    FN: IsTStr,
    const SIZE: usize,
>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    legacy_key_name: &str,
    key_table_name: &str,
) -> Result<Result<KeyFromDisk<FN, SIZE>, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    // read both key sources
    let legacy_key_file =
        get_as_opt_path_buf(raw, file_path, table, table_span.clone(), legacy_key_name)
            .process_parse_result(&mut errors)
            .flatten();
    let key_table =
        get_as_opt_inline_table(raw, file_path, table, table_span.clone(), key_table_name)
            .process_parse_result(&mut errors)
            .flatten();
    let key: Result<KeyFromDisk<FN, SIZE>, ParseError> = match (legacy_key_file, key_table) {
        // duplicate definition
        (Some(_), Some(_)) => {
            let err = ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(legacy_key_name),
                format!(
                    "keys \"{l}\" and \"{key_table_name}\" {} \"{l}\" {}",
                    "are mutually exclusive and",
                    "is deprecated",
                    l = legacy_key_name
                ),
            );
            errors.push(err.clone());
            Err(err)
        }
        // missing key
        (None, None) => Err(ParseError::new(
            raw,
            file_path,
            table_span.clone(),
            format!("expected key \"{key_table_name}\""),
        )),
        // legacy key
        (Some(legacy_key_file), None) => Ok(KeyFromDisk::new(
            <KeyFromDisk<FN, SIZE> as HasInnerType>::InnerType::File(legacy_key_file),
        )),
        // new key table
        (None, Some(table)) => {
            const FILE_NAME: &str = "public-key-file";
            const DIR_NAME: &str = "public-key-directory";

            // TODO: use particularly strong wording for this error?
            deny_illegal_keys(raw, file_path, table, vec![FILE_NAME, DIR_NAME])
                .process_parse_result(&mut errors);

            let key = get_key_from_disk(
                raw,
                file_path,
                table,
                table.span(),
                false,
                FILE_NAME,
                DIR_NAME,
            )
            .process_parse_result(&mut errors);

            if !errors.is_empty() {
                return Err(errors);
            }
            key.expect("unreachable")
        }
    };
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(key)
}

// Keypair<S: KeyFromDisk, P: KeyFromDisk>
get_as_type_generator!(
    get_as_keypair_with_pub_from_disk,
    get_as_opt_keypair_with_pub_from_disk,
    [SFN: IsTStr, const SSIZE: usize, PFN: IsTStr, const PSIZE: usize],
    Keypair<KeyFromDisk<SFN, SSIZE>, KeyFromDisk<PFN, PSIZE>>,
    as_inline_table,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();

        // read secret and public key (both optional for now)
        const SECRETFILE: &str = "secret-key-file";
        const SECRETDIR: &str = "secret-key-directory";
        const PUBFILE: &str = "public-key-file";
        const PUBDIR: &str = "public-key-directory";
        let secret_key = get_key_from_disk(raw,
                        file_path,table, table.span(), false, SECRETFILE, SECRETDIR)
            .process_parse_result(&mut errors);
        let public_key = get_key_from_disk(raw,
                        file_path,table, table.span(), false, PUBFILE, PUBDIR)
            .process_parse_result(&mut errors);

        deny_illegal_keys(raw,
                        file_path,table, vec![SECRETFILE, SECRETDIR, PUBFILE, PUBDIR])
            .process_parse_result(&mut errors);

        // return on error (parse errors, but not missing keys – they are optional this far)
        if !errors.is_empty() {
            return Err(errors);
        }

        // make secret and pubic key both required (no longer optional)
        let secret_key = secret_key.guaranteed_unwrap().process_parse_result(&mut errors);
        let public_key = public_key.guaranteed_unwrap().process_parse_result(&mut errors);

        // return
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Keypair {
            secret_key_source: secret_key.guaranteed_unwrap(),
            public_key_source: public_key.guaranteed_unwrap(),
        })
    }
);

// TODO: Rust formatter does not work on this function
// Keypair<S: KeyFromDisk, P: KeyFromDiskOrB64EncodedString>
get_as_type_generator!(
    get_as_keypair_with_pub_from_disk_or_b64,
    get_as_opt_keypair_with_pub_from_disk_or_b64,
    [SFN: IsTStr, const SSIZE: usize, PFN: IsTStr, const PSIZE: usize],
    Keypair<KeyFromDisk<SFN, SSIZE>, KeyFromDiskOrB64EncodedString<PFN, PSIZE>>,
    as_inline_table,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();

        // read secret and public key (both optional for now)
        const SECRETFILE: &str = "secret-key-file";
        const SECRETDIR: &str = "secret-key-directory";
        const PUBFILE: &str = "public-key-file";
        const PUBDIR: &str = "public-key-directory";
        const PUBINLINE: &str = "public-key";

        let secret_key = get_key_from_disk(
            raw,
                        file_path,table, table.span(), false, SECRETFILE, SECRETDIR
            )
            .process_parse_result(&mut errors);
        let public_key = get_key_from_disk_or_b64(
            raw,
                        file_path,table, table.span(), false, PUBFILE, PUBDIR,PUBINLINE)
            .process_parse_result(&mut errors);

        deny_illegal_keys(raw,
                        file_path,table,
                        vec![SECRETFILE, SECRETDIR, PUBFILE, PUBDIR, PUBINLINE]
        )
            .process_parse_result(&mut errors);

        // return on error (parse errors, but not missing keys – they are optional this far)
        if !errors.is_empty() {
            return Err(errors);
        }

        // make secret and pubic key both required (no longer optional)
        let secret_key = secret_key.guaranteed_unwrap().process_parse_result(&mut errors);
        let public_key = public_key.guaranteed_unwrap().process_parse_result(&mut errors);




        if !errors.is_empty() {
            return Err(errors);
        }
        let keypair = Keypair {
            secret_key_source: secret_key.guaranteed_unwrap(),
            public_key_source: public_key.guaranteed_unwrap(),
        };
        Ok(keypair)
    }
);

/// reads a [`Keypair<KeyFromDisk>`] from either legacy or new keypair definition
///
/// legacy:
/// ```toml
/// secret_key = "path/to/secret-file"
/// public_key = "path/to/public-file"
/// ```
///
/// new (the new name can be specified as function parameter `new_name`):
/// ```toml
/// __new_name__ = {
///     secret-key-file = "path/to/secret-file"
///     # alternative: secret-key-directory = "/path/to/public-dir"
///
///     public-key-file = "path/to/public-file"
///     # alternative: public-key-directory = "/path/to/public-dir"
/// }
/// ```
pub(crate) fn get_legacy_keypair_from_disk<
    T: toml_edit::TableLike,
    SFN: IsTStr,
    const SSIZE: usize,
    PFN: IsTStr,
    const PSIZE: usize,
>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    legacy_secret_name: &str,
    legacy_public_name: &str,
    new_name: &str,
) -> Result<Keypair<KeyFromDisk<SFN, SSIZE>, KeyFromDisk<PFN, PSIZE>>, Vec<ParseError>> {
    let mut errors = Vec::new();

    let legacy_secret = get_as_opt_path_buf(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_secret_name,
    )
    .process_parse_result(&mut errors)
    .flatten();
    let legacy_public = get_as_opt_path_buf(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_public_name,
    )
    .process_parse_result(&mut errors)
    .flatten();
    let new =
        get_as_opt_keypair_with_pub_from_disk(raw, file_path, table, table_span.clone(), new_name)
            .process_parse_result(&mut errors)
            .flatten();

    if !errors.is_empty() {
        return Err(errors);
    }

    let keypair = match (legacy_secret, legacy_public, new) {
        // missing keys
        (None, None, None) => {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                table_span.clone(),
                format!("expected key \"{new_name}\""),
            )]);
        }
        (None, Some(_), None) => {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                table_span.clone(),
                format!("expected key \"{legacy_secret_name}\""),
            )]);
        }
        (Some(_), None, None) => {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                table_span.clone(),
                format!("expected key \"{legacy_public_name}\""),
            )]);
        }

        // conflicting keys
        (None, Some(_), Some(_)) => {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(legacy_public_name),
                format!(
                    "keys \"{legacy_public_name}\" and \"{new_name}\" are mutually exclusive and \"{legacy_public_name}\" is deprecated"
                ),
            )]);
        }
        (Some(_), None, Some(_)) => {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(legacy_secret_name),
                format!(
                    "keys \"{legacy_secret_name}\" and \"{new_name}\" are mutually exclusive and \"{legacy_secret_name}\" is deprecated"
                ),
            )]);
        }
        (Some(_), Some(_), Some(_)) => {
            return Err(vec![ParseError::new(
                raw,
                file_path,
                table.get_key_value_span(legacy_secret_name),
                format!(
                    "keys \"{legacy_secret_name}\" and \"{legacy_public_name}\" (deprecated keypair definition) can not be used together with \"{new_name}\""
                ),
            )]);
        }

        // legacy keypair
        (Some(secret), Some(public), None) => Keypair {
            secret_key_source: KeyFromDisk::<SFN, SSIZE>::new(KeyFromDiskInner::File(secret)),
            public_key_source: KeyFromDisk::<PFN, PSIZE>::new(KeyFromDiskInner::File(public)),
        },

        // new keypair
        (None, None, Some(keypair)) => keypair,
    };

    if !errors.is_empty() {
        log::error!("unreachable code in {}:{}", file!(), line!());
        return Err(errors);
    }
    Ok(keypair)
}

get_as_type_generator!(
    get_as_config_file_version,
    get_as_opt_config_file_version,
    [],
    TomlConfigFileVersion,
    as_str,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, s: &str| {
        const V1: &str = "1";
        if s == V1 {
            Ok(TomlConfigFileVersion::Version1)
        } else {
            Err(vec![ParseError::new(
                raw,
                file_path,
                item.span(),
                format!("invalid config file version; supported values are \"{V1}\""),
            )])
        }
    }
);

#[cfg(feature = "experiment_api")]
get_as_type_generator!(
    get_as_api_config,
    get_as_opt_api_config,
    [],
    ApiConfig,
    as_table_like,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, table: &dyn toml_edit::TableLike| {
        let mut errors = Vec::new();

        const LISTEN_PATH: &str = "listen-path";
        const LISTEN_FD: &str = "listen-fd";
        const STREAM_FD: &str = "stream-fd";

        let listen_path = get_as_vec_path_buf(raw, file_path, table, item.span(), LISTEN_PATH)
            .process_parse_result(&mut errors);
        let listen_fd = get_as_vec_i32(raw, file_path, table, item.span(), LISTEN_FD)
            .process_parse_result(&mut errors);
        let stream_fd = get_as_vec_i32(raw, file_path, table, item.span(), STREAM_FD)
            .process_parse_result(&mut errors);

        deny_illegal_keys(
            raw,
            file_path,
            table,
            vec![LISTEN_PATH, LISTEN_FD, STREAM_FD],
        )
        .process_parse_result(&mut errors);

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(ApiConfig {
            listen_path: listen_path.expect("unreachable"),
            listen_fd: listen_fd.expect("unreachable"),
            stream_fd: stream_fd.expect("unreachable"),
        })
    }
);

pub(crate) fn default_peer_name(index: usize) -> String {
    format!("peer no. {index}")
}

pub(crate) fn get_array_of_tables<'a>(
    raw: &'a str,
    file_path: &'a Path,
    document: &'a toml_edit::Document<String>,
    name: &'a str,
) -> Result<&'a ArrayOfTables, Vec<ParseError>> {
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
}

pub(crate) fn get_opt_array_of_tables<'a>(
    raw: &'a str,
    file_path: &'a Path,
    document: &'a toml_edit::Document<String>,
    name: &'a str,
) -> Result<Option<&'a ArrayOfTables>, Vec<ParseError>> {
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
}

get_as_type_generator!(
    get_as_key_out,
    get_as_opt_key_out,
    [],
    OutputToFileConfig,
    as_inline_table,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();

        const ENABLED: &str = "enabled";
        const FILE: &str = "file";
        const OSK_DOMAIN_SEPARATOR: &str = "osk-domain-separator";

        deny_illegal_keys(
            raw,
            file_path,
            table,
            vec![ENABLED, FILE, OSK_DOMAIN_SEPARATOR],
        )
        .process_parse_result(&mut errors);

        let enabled = get_as_opt_bool(raw, file_path, table, table.span(), ENABLED)
            .process_parse_result(&mut errors)
            .flatten()
            .unwrap_or(true); // default to true

        let file = get_as_path_buf(raw, file_path, table, table.span(), FILE)
            .process_parse_result(&mut errors);

        let osk_domain_separator = get_as_opt_osk_domain_separator(
            raw,
            file_path,
            table,
            table.span(),
            OSK_DOMAIN_SEPARATOR,
        )
        .process_parse_result(&mut errors)
        .flatten()
        .unwrap_or_default(); // defaults to empty OSK domain separator

        // return
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(OutputToFileConfig {
            enabled,
            output_file_path: file.guaranteed_unwrap(),
            osk_domain_separator,
        })
    }
);

pub(crate) fn get_legacy_key_output<T: toml_edit::TableLike>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    legacy_name: &str,
    modern_name: &str,
) -> Result<Result<OutputToFileConfig, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    // parse both legacy and modern semantic
    let legacy = get_as_opt_path_buf(raw, file_path, table, table_span.clone(), legacy_name)
        .process_parse_result(&mut errors)
        .flatten();

    let modern = get_as_opt_key_out(raw, file_path, table, table_span.clone(), modern_name)
        .process_parse_result(&mut errors)
        .flatten();

    // return on error
    if !errors.is_empty() {
        return Err(errors);
    }

    // decide which definition to use (legacy / modern)
    let key_out = match (legacy, modern) {
        // none sepcified
        (None, None) => Err(ParseError::new(
            raw,
            file_path,
            table_span.clone(),
            format!("missing key \"{modern_name}\""),
        )),
        // conflicting keys
        (Some(_), Some(_)) => {
            let span = table.key(legacy_name).guaranteed_unwrap().span();
            let err = ParseError::new_ext(
                raw,
                file_path,
                span,
                format!(
                    "conflicting keys \"{l}\" and \"{m}\" – use \"{m}\" because \"{l}\" is deprecated",
                    l = legacy_name,
                    m = modern_name
                ),
                "conflicting key here should be removed",
            );
            errors.push(err.clone());
            Err(err)
        }
        // legacy definition
        (Some(legacy), None) => Ok(OutputToFileConfig {
            enabled: true,
            output_file_path: legacy,
            osk_domain_separator: RosenpassPeerOskDomainSeparator::default(), // defaults to empty
        }),
        // modern definition
        (None, Some(modern)) => Ok(modern),
    };

    // return
    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(key_out)
}

get_as_type_generator!(
    get_as_wireguard_options,
    get_as_opt_wireguard_options,
    [],
    PeerWireguardOptions,
    as_inline_table,
    |raw: &str, file_path: &Path, item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();
        let table_span = table.span();

        const ENDPOINT: &str = "endpoint";
        const PERSISTENT_KEEPALIVE: &str = "persistent-keepalive";
        const ALLOWED_IPS: &str = "allowed-ips";
        const WG_EXTRA_ARGUMENTS: &str = "wg-extra-arguments";

        deny_illegal_keys(
            raw,
            file_path,
            table,
            vec![
                ENDPOINT,
                PERSISTENT_KEEPALIVE,
                ALLOWED_IPS,
                WG_EXTRA_ARGUMENTS,
            ],
        )
        .process_parse_result(&mut errors);

        let endpoint = get_as_opt_string(raw, file_path, table, table_span.clone(), ENDPOINT)
            .process_parse_result(&mut errors)
            .flatten();

        let persistent_keepalive = get_as_opt_unsigned_integer(
            raw,
            file_path,
            table,
            table_span.clone(),
            PERSISTENT_KEEPALIVE,
        )
        .process_parse_result(&mut errors)
        .flatten()
        .map(|u| u as usize);

        let allowed_ips =
            get_as_opt_vec_ip_cidr(raw, file_path, table, table_span.clone(), ALLOWED_IPS)
                .process_parse_result(&mut errors)
                .flatten();

        let wg_extra_arguments = get_as_opt_vec_string(
            raw,
            file_path,
            table,
            table_span.clone(),
            WG_EXTRA_ARGUMENTS,
        )
        .process_parse_result(&mut errors)
        .flatten()
        .unwrap_or_default(); // default to empty list

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(PeerWireguardOptions {
            endpoint,
            persistent_keepalive,
            allowed_ips,
            wg_extra_arguments,
        })
    }
);

// DeviceWireguardOptions
get_as_type_generator!(
    get_as_device_wireguard_options,
    get_as_opt_device_wireguard_options,
    [],
    DeviceWireguardOptions,
    as_inline_table,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();

        const WG_LISTEN_PORT: &str = "listen-port";
        const WG_FWMARK: &str = "fwmark";

        deny_illegal_keys(raw, file_path, table, vec![WG_LISTEN_PORT, WG_FWMARK])
            .process_parse_result(&mut errors);

        let wg_listen_port = get_as_opt_u16(raw, file_path, table, table.span(), WG_LISTEN_PORT)
            .process_parse_result(&mut errors)
            .flatten();

        let wg_fwmark = get_as_opt_u16(raw, file_path, table, table.span(), WG_FWMARK)
            .process_parse_result(&mut errors)
            .flatten();

        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(DeviceWireguardOptions {
            wg_listen_port,
            wg_fwmark,
        })
    }
);

get_as_type_generator!(
    get_as_wireguard,
    get_as_opt_wireguard,
    [],
    WireguardConfig,
    as_inline_table,
    |raw: &str, file_path: &Path, _item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();
        let table_span = table.span();

        const ENABLED: &str = "enabled";
        const DEVICE: &str = "device";
        const OUR_WG_KEYPAIR: &str = "our-wireguard-keypair";
        const THEIR_WG_KEYPAIR: &str = "their-wireguard-keypair";
        const WG_OPTIONS: &str = "wireguard-options";
        const EXCHANGE_COMMAND: &str = "exchange-command";
        const OSK_DOMAIN_SEPARATOR: &str = "osk-domain-separator";

        deny_illegal_keys(
            raw,
            file_path,
            table,
            vec![
                ENABLED,
                DEVICE,
                OUR_WG_KEYPAIR,
                THEIR_WG_KEYPAIR,
                WG_OPTIONS,
                EXCHANGE_COMMAND,
                OSK_DOMAIN_SEPARATOR,
            ],
        )
        .process_parse_result(&mut errors);

        let enabled = get_as_opt_bool(raw, file_path, table, table_span.clone(), ENABLED)
            .process_parse_result(&mut errors)
            .flatten()
            .unwrap_or(true); // keys named "enabled" always defaults to true throughout the config

        let device = get_as_string(raw, file_path, table, table_span.clone(), DEVICE)
            .process_parse_result(&mut errors);

        let our_wireguard_keypair = get_as_opt_keypair_with_pub_from_disk_or_b64(
            raw,
            file_path,
            table,
            table_span.clone(),
            OUR_WG_KEYPAIR,
        )
        .process_parse_result(&mut errors)
        .flatten();

        let their_wireguard_public_key =
            get_as_opt_inline_table(raw, file_path, table, table_span.clone(), THEIR_WG_KEYPAIR)
                .process_parse_result(&mut errors)
                .flatten()
                .and_then(|table| {
                    get_key_from_disk_or_b64(
                        raw,
                        file_path,
                        table,
                        table.span(),
                        true,
                        "public-key-file",
                        "public-key-directory",
                        "public-key",
                    )
                    .process_parse_result(&mut errors)
                    // make key required
                    .transpose()
                    .process_parse_result(&mut errors)
                    .flatten()
                });

        let wireguard_options =
            get_as_opt_wireguard_options(raw, file_path, table, table_span.clone(), WG_OPTIONS)
                .process_parse_result(&mut errors)
                .flatten()
                .unwrap_or_default(); // defaults to empty wireguard options

        let exchange_command =
            get_as_opt_vec_string(raw, file_path, table, table_span.clone(), EXCHANGE_COMMAND)
                .process_parse_result(&mut errors)
                .flatten();

        let osk_domain_separator = get_as_opt_osk_domain_separator(
            raw,
            file_path,
            table,
            table_span.clone(),
            OSK_DOMAIN_SEPARATOR,
        )
        .process_parse_result(&mut errors)
        .flatten()
        .unwrap_or_default(); // default to empty OSK domain separator

        // return early if an error occured so far
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(WireguardConfig {
            enabled,
            device_name: device.guaranteed_unwrap(),
            our_wireguard_keypair: our_wireguard_keypair.map(|our_wireguard_keypair| {
                OurWireguardKeypair::EntireKeypair(our_wireguard_keypair)
            }),
            their_wireguard_public_key,
            wireguard_options,
            exchange_command,
            osk_domain_separator,
        })
    }
);

pub(crate) fn get_legacy_wireguard<T: toml_edit::TableLike>(
    raw: &str,
    file_path: &Path,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    legacy_device_name: &str,
    legacy_their_pubkey_name: &str,
    legacy_our_pubkey_name: &str,
    legacy_extra_params_name: &str,
    legacy_exchange_command_name: &str,
    modern_name: &str,
) -> Result<Result<WireguardConfig, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    // read both legacy and modern definition
    let legacy_device = get_as_opt_string(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_device_name,
    )
    .process_parse_result(&mut errors)
    .flatten();

    let legacy_their_pubkey = get_as_opt_path_buf(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_their_pubkey_name,
    )
    .process_parse_result(&mut errors)
    .flatten();

    let legacy_our_pubkey = get_as_opt_string(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_our_pubkey_name,
    )
    .process_parse_result(&mut errors)
    .flatten();

    let legacy_extra_params = get_as_opt_vec_string(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_extra_params_name,
    )
    .process_parse_result(&mut errors)
    .flatten();

    let legacy_exchange_command = get_as_opt_vec_string(
        raw,
        file_path,
        table,
        table_span.clone(),
        legacy_exchange_command_name,
    )
    .process_parse_result(&mut errors)
    .flatten();

    let modern = get_as_opt_wireguard(raw, file_path, table, table_span.clone(), modern_name)
        .process_parse_result(&mut errors)
        .flatten();

    // return if parse errors already occured so far
    if !errors.is_empty() {
        return Err(errors);
    }

    // quirk: in legacy config, the device used to be set via `exchange_command`
    let legacy_device_quirk = legacy_device.clone().or_else(|| {
        match legacy_exchange_command.clone() {
            None => None,
            Some(legacy_exchange_command) => {
                if legacy_exchange_command.get(1).is_some_and(|s| s == "set")
                    && let Some(dev) = legacy_exchange_command.get(2)
                {
                    // it is very likely that this is an exchange command to define the WG device
                    Some(dev.clone())
                } else {
                    None
                }
            }
        }
    });
    // quirk: in legacy config, users could define their own wg binary
    if legacy_exchange_command
        .clone()
        .is_some_and(|cmd| cmd.get(0).is_some_and(|cmd| cmd != "wg"))
    {
        errors.push(ParseError::new_ext(
            raw,
            file_path,
            table.get_key_value_span(legacy_exchange_command_name),
            "custom wg binary is no longer supported",
            format!("this \"{legacy_exchange_command_name}\" will not work as expected"),
        ));
    }
    // return if quirk errors occured so far
    if !errors.is_empty() {
        return Err(errors);
    }

    // catch legacy definition
    match (legacy_device_quirk, legacy_exchange_command.clone()) {
        // not a legacy definition
        (None, None) => (),
        // strange legacy definition
        (None, _) => {
            return Err(vec![ParseError::new_ext(
                raw,
                file_path,
                table.get_key_value_span(legacy_exchange_command_name),
                "specific exchange command no longer supported",
                "should start with `wg set <DEV> ...`",
            )]);
        }
        // legacy keys combined with a modern definition conflict – error is handled further down
        (Some(_), _) if modern.is_some() => (),
        // classic legacy definition
        (Some(legacy_device_quirk), _) => {
            return Ok(Ok(WireguardConfig {
                enabled: true,
                device_name: legacy_device_quirk,
                // yes, our WG keypair is indeed always a base64-encoded pubkey in the legacy format
                // introduced in https://github.com/rosenpass/rosenpass/pull/1171
                our_wireguard_keypair: legacy_our_pubkey.clone().map(|legacy_our_pubkey| {
                    OurWireguardKeypair::PublicKeyOnly(KeyFromDiskOrB64EncodedString::new(
                        KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(legacy_our_pubkey),
                    ))
                }),
                // TODO: check if the legacy format for their pubkey is always a file or whether it can
                // also be a directory or base64-encoded
                their_wireguard_public_key: legacy_their_pubkey.clone().map(
                    |legacy_their_pubkey| {
                        KeyFromDiskOrB64EncodedString::new(
                            KeyFromDiskOrB64EncodedStringInner::File(legacy_their_pubkey),
                        )
                    },
                ),
                wireguard_options: PeerWireguardOptions {
                    endpoint: None,
                    persistent_keepalive: None,
                    allowed_ips: None,
                    wg_extra_arguments: legacy_extra_params.unwrap_or_default(), // default to empty
                },
                exchange_command: legacy_exchange_command.clone(),
                osk_domain_separator: RosenpassPeerOskDomainSeparator::default(), // default to empty
            }));
        }
    }

    // catch modern option, missing definition and conflicting keys
    let wireguard: Result<WireguardConfig, ParseError> = match (
        legacy_device,
        legacy_their_pubkey.clone(),
        legacy_our_pubkey.clone(),
        legacy_extra_params,
        legacy_exchange_command,
        modern,
    ) {
        // modern definition
        (None, None, None, None, None, Some(modern)) => Ok(modern),

        // none specified
        (None, None, None, None, None, None) => Err(ParseError::new(
            raw,
            file_path,
            table_span,
            format!("expected key {modern_name}"),
        )),

        // conflicting keys – put out an elaborate error message
        _ => {
            let all_legacy_keys = vec![
                legacy_device_name,
                legacy_their_pubkey_name,
                legacy_our_pubkey_name,
                legacy_extra_params_name,
                legacy_exchange_command_name,
            ];
            let all_used_legacy_keys = all_legacy_keys
                .clone()
                .into_iter()
                .filter(|s| table.contains_key(s))
                .collect::<Vec<_>>();
            let all_used_legacy_keys_joined = all_used_legacy_keys
                .clone()
                .into_iter()
                .map(|x| format!("\"{x}\""))
                .collect::<Vec<_>>()
                .join(", ");
            let all_legacy_keys_joined = all_legacy_keys
                .clone()
                .into_iter()
                .map(|x| format!("\"{x}\""))
                .collect::<Vec<_>>()
                .join(", ");
            // list of legacy names and their positions
            let legacy_list = all_used_legacy_keys
                .clone()
                .into_iter()
                .filter_map(|string| table.get_key_value_span(string).map(|span| (string, span)))
                .collect::<Vec<_>>();
            // the legacy item, the error message will try to point to
            let legacy_item = legacy_list.first();
            // point to legacy item or alternatively to modern item
            let span = legacy_item
                .map(|(_string, span)| span.clone())
                .or(table.get_key_span(modern_name));

            let err = ParseError::new_ext(
                raw,
                file_path,
                span,
                format!(
                    "conflicting keys: \"{modern_name}\" is not compatible with legacy wireguard keys {l}",
                    l = all_used_legacy_keys_joined
                ),
                match legacy_item {
                    Some((_name, _span)) => {
                        format!(
                            "remove this legacy item in favor of \"{modern_name}\" {} {}",
                            "– alternatively, supply all necessary legacy options:",
                            all_legacy_keys_joined
                        )
                    }
                    None => format!("use \"{modern_name}\" instead of the legacy items"),
                },
            );
            errors.push(err.clone());
            Err(err)
        }
    };

    if !errors.is_empty() {
        return Err(errors);
    }
    Ok(wireguard)
}
