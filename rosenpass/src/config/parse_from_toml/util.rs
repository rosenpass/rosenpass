use super::errors::ParseError;
use crate::{
    config::{
        KeyFromDisk, KeyFromDiskInner, Keypair, NewFromInner, PresharedKeySource,
        TomlConfigFileVersion,
    },
    oldconfig::{RosenpassPeerOskDomainSeparator, Verbosity},
    protocol::ProtocolVersion,
};
use log::LevelFilter;
use serde::{Deserialize, de::value::StrDeserializer};
use std::{collections::HashSet, str::FromStr};
use toml_edit::InlineTable;
use tstr::IsTStr;

/// can be used on the output of `get_as_*()` if `let mut errors: Parse<Error> = Vec::new();` has been defined
macro_rules! process_results {
    ($errors: expr, $result: expr) => {
        $result.map(|v| Some(v)).unwrap_or_else(|err| {
            $errors.extend_from_slice(&err);
            None
        })
    };
}
pub(crate) use process_results;
/// can be used on the output of `get_as_*()` if `let mut errors: Parse<Error> = Vec::new();` has been defined
macro_rules! process_result {
    ($errors: expr, $result: expr) => {
        $result.map(|v| Some(v)).unwrap_or_else(|err| {
            $errors.push(err);
            None
        })
    };
}
#[allow(unused_imports)]
pub(crate) use process_result;

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
            .filter_map(|x| x.as_ref().err().clone())
            .map(|x| x.clone())
            .flatten()
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
            .filter_map(|x| x.as_ref().err().clone())
            .map(|x| x.clone())
            .collect::<Vec<ParseError>>();
        error_list.extend_from_slice(&errors);
        if errors.is_empty() {
            Some(self.into_iter().map(|x| x.expect("unreachable")).collect())
        } else {
            None
        }
    }
}

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
    ($fn_name: ident, $opt_fn_name: ident, [$($generics:tt)*], $type_: ty, $getter: ident, $mapper: expr) => {
        #[allow(dead_code)]
        pub fn $fn_name<'a, TableLike: toml_edit::TableLike, $($generics)*>(
            raw: &'a str,
            table: &'a TableLike,
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
        pub fn $opt_fn_name<'a, TableLike: toml_edit::TableLike, $($generics)*>(
            raw: &'a str,
            table: &'a TableLike,
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

// String
get_as_type_generator!(
    get_as_string,
    get_as_opt_string,
    [],
    String,
    as_str,
    |_: &str, _: &toml_edit::Item, s: &str| -> Result<_, Vec<ParseError>> { Ok(s.to_string()) }
);

// i64
get_as_type_generator!(
    get_as_integer,
    get_as_opt_integer,
    [],
    i64,
    as_integer,
    |_: &str, _: &toml_edit::Item, i| -> Result<_, Vec<ParseError>> { Ok(i64::from(i)) }
);

// u64
get_as_type_generator!(
    get_as_unsigned_integer,
    get_as_opt_unsigned_integer,
    [],
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

// u16
get_as_type_generator!(
    get_as_u16,
    get_as_opt_u16,
    [],
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

// bool
get_as_type_generator!(
    get_as_bool,
    get_as_opt_bool,
    [],
    bool,
    as_bool,
    |_: &str, _: &toml_edit::Item, b| -> Result<_, Vec<ParseError>> { Ok(b) }
);

// log::LevelFilter
get_as_type_generator!(
    get_as_log_level,
    get_as_opt_log_level,
    [],
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

// config::Verbosity
get_as_type_generator!(
    get_as_verbosity_level,
    get_as_opt_verbosity_level,
    [],
    Verbosity,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        Verbosity::deserialize(StrDeserializer::<serde::de::value::Error>::new(s))
            .map_err(|err| vec![ParseError::new(raw, item.span(), format!("{err}"))])
    }
);

// PathBuf
get_as_type_generator!(
    get_as_path_buf,
    get_as_opt_path_buf,
    [],
    std::path::PathBuf,
    as_str,
    |_raw: &str, _item: &toml_edit::Item, s: &str| -> Result<_, Vec<ParseError>> {
        Ok(std::path::PathBuf::from(s))
    }
);

// toml_edit::Array
get_as_type_generator!(
    get_as_array,
    get_as_opt_array,
    [],
    &'a toml_edit::Array,
    as_array,
    |_, _, list: &'a toml_edit::Array| -> Result<_, Vec<ParseError>> { Ok(list) }
);

// toml_edit::InlineTable
get_as_type_generator!(
    get_as_inline_table,
    get_as_opt_inline_table,
    [],
    &'a toml_edit::InlineTable,
    as_inline_table,
    |_, _, tab: &'a toml_edit::InlineTable| -> Result<_, Vec<ParseError>> { Ok(tab) }
);

// Vec<String>
get_as_type_generator!(
    get_as_vec_string,
    get_as_opt_vec_string,
    [],
    Vec<String>,
    as_array,
    |raw: &'a str, _item: &'a toml_edit::Item, array: &'a toml_edit::Array| {
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

// ProtocolVersion
pub(crate) fn as_protocol_version(
    raw: &str,
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
    |raw: &str, item: &toml_edit::Item, s: &str| { as_protocol_version(raw, item, s) }
);
get_as_type_generator!(
    get_as_hashset_protocol_version,
    get_as_opt_hashset_protocol_version,
    [],
    HashSet<ProtocolVersion>,
    as_array,
    |raw: &str, item: &toml_edit::Item, array: &toml_edit::Array| {
        let mut errors = Vec::new();

        // map to Array of Strings
        let array = array
            .iter()
            .map(|item| -> Result<String, ParseError> {
                item.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    ParseError::new(raw, item.span(), "expected array of strings".to_string())
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
            .map(|x| as_protocol_version(raw, item, x))
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
                item.span(),
                format!("duplicate values in set of protocol versions"),
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
    std::net::SocketAddr,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        std::net::SocketAddr::from_str(s)
            .map_err(|err| vec![ParseError::new(raw, item.span(), err.to_string())])
    }
);

// OSK Domain Separator
get_as_type_generator!(
    get_as_osk_domain_separator,
    get_as_opt_osk_domain_separator,
    [],
    RosenpassPeerOskDomainSeparator,
    as_inline_table,
    |raw: &str, _item: &toml_edit::Item, inline_table: &InlineTable| {
        let mut errors = Vec::new();
        const ORG: &str = "organization";
        const LABELS: &str = "labels";

        // read "organization"
        let organization = get_as_string(raw, inline_table, inline_table.span(), ORG)
            .process_parse_result(&mut errors);

        // read "labels"
        let osk_labels = get_as_vec_string(raw, inline_table, inline_table.span(), LABELS)
            .process_parse_result(&mut errors);

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

// OSK Domain Separator (legacy-aware)
pub(crate) fn get_legacy_osk_domain_separator<T: toml_edit::TableLike>(
    raw: &str,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
) -> Result<RosenpassPeerOskDomainSeparator, Vec<ParseError>> {
    let mut errors = Vec::new();
    const LEGACY_ORG: &str = "osk_organization";
    const LEGACY_LABELS: &str = "osk_label";
    const TABLE: &str = "osk-domain-separator";

    let legacy_org = get_as_opt_string(raw, table, table_span.clone(), LEGACY_ORG)
        .process_parse_result(&mut errors)
        .flatten();

    let legacy_labels = get_as_opt_vec_string(raw, table, table_span.clone(), LEGACY_LABELS)
        .process_parse_result(&mut errors)
        .flatten();

    let osk_table = get_as_opt_inline_table(raw, table, table_span.clone(), TABLE)
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
                format!("keys \"{LEGACY_ORG}\" and \"{TABLE}\" are mutually exclusive and \"{LEGACY_ORG}\" is deprecated"))
            );
            None
        }
        (None, Some(_), Some(_)) => {
            errors.push(ParseError::new(raw, table_span.clone(),
                format!("keys \"{LEGACY_LABELS}\" and \"{TABLE}\" are mutually exclusive and \"{LEGACY_LABELS}\" is deprecated"))
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
            let org = get_as_string(raw, osk_table, osk_table.span(), ORG)
                .process_parse_result(&mut errors);
            let labels = get_as_vec_string(raw, osk_table, osk_table.span(), LABELS)
                .process_parse_result(&mut errors);
            deny_illegal_keys(raw, osk_table, vec![ORG, LABELS]).process_parse_result(&mut errors);
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
    |raw: &str, _item: &toml_edit::Item, inline_table: &InlineTable| {
        const FILE: &str = "file";
        const DIR: &str = "directory";
        let mut errors = Vec::new();

        let file = get_as_opt_path_buf(raw, inline_table, inline_table.span(), "file")
            .process_parse_result(&mut errors)
            .flatten();
        let dir = get_as_opt_path_buf(raw, inline_table, inline_table.span(), "directory")
            .process_parse_result(&mut errors)
            .flatten();

        // check that `inline_table` has no further keys (e.g. no plaintext PSK)
        deny_illegal_keys(raw, inline_table, vec![FILE, DIR]).process_parse_result(&mut errors);

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

/// reads a key source which can either be a file or a directory ([`KeyFromDisk`])
///
/// returns:
/// - `Ok(Ok(KeyFromDisk))` if the key was successfully read
/// - `Err(Vec<ParseError>)` if errors occured during parsing
/// - `Ok(Err(ParseError))` if the key is not present in the table
pub(crate) fn get_key_from_disk<T: toml_edit::TableLike, FN: IsTStr>(
    raw: &str,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    file_key: &str,
    dir_key: &str,
) -> Result<Result<KeyFromDisk<FN>, ParseError>, Vec<ParseError>> {
    let mut errors = Vec::new();

    let file = get_as_opt_path_buf(raw, table, table_span.clone(), file_key)
        .process_parse_result(&mut errors)
        .flatten();
    let dir = get_as_opt_path_buf(raw, table, table_span.clone(), dir_key)
        .process_parse_result(&mut errors)
        .flatten();

    let key = match (file, dir) {
        (None, None) => Err(ParseError::new(
            raw,
            table_span.clone(),
            format!("expected either key \"{file_key}\" or \"{dir_key}\""),
        )),
        (Some(_), Some(_)) => {
            let err = ParseError::new(
                raw,
                table_span.clone(),
                format!("keys \"{file_key}\" and \"{dir_key}\" are mutually exclusive"),
            );
            errors.push(err.clone());
            // the err is just a dummy in this line – the function will return Err(errors) anyways
            Err(err)
        }
        (Some(file), None) => Ok(KeyFromDisk::<FN>::new(KeyFromDiskInner::File(file))),
        (None, Some(dir)) => Ok(KeyFromDisk::<FN>::new(KeyFromDiskInner::Directory(dir))),
    };

    if errors.is_empty() {
        Ok(key)
    } else {
        Err(errors)
    }
}

// Keypair<S: KeyFromDisk, P: KeyFromDisk>
get_as_type_generator!(
    get_as_keypair_with_pub_from_disk,
    get_as_opt_keypair_with_pub_from_disk,
    [SFN: IsTStr, PFN: IsTStr],
    Keypair<KeyFromDisk<SFN>, KeyFromDisk<PFN>>,
    as_inline_table,
    |raw: &str, _item: &toml_edit::Item, table: &toml_edit::InlineTable| {
        let mut errors = Vec::new();

        // read secret and public key (both optional for now)
        const SECRETFILE: &str = "secret-key-file";
        const SECRETDIR: &str = "secret-key-directory";
        const PUBFILE: &str = "public-key-file";
        const PUBDIR: &str = "public-key-directory";
        let secret_key = get_key_from_disk(raw, table, table.span(), SECRETFILE, SECRETDIR)
            .process_parse_result(&mut errors);
        let public_key = get_key_from_disk(raw, table, table.span(), PUBFILE, PUBDIR)
            .process_parse_result(&mut errors);

        deny_illegal_keys(raw, table, vec![SECRETFILE, SECRETDIR, PUBFILE, PUBDIR])
            .process_parse_result(&mut errors);

        // return on error (parse errors, but not missing keys – they are optional this far)
        if !errors.is_empty() {
            return Err(errors);
        }
        let secret_key = secret_key.unwrap();
        let public_key = public_key.unwrap();

        // make secret and pubic key both required (no longer optional)
        let secret_key = process_result!(errors, secret_key);
        let public_key = process_result!(errors, public_key);

        // return
        if !errors.is_empty() {
            return Err(errors);
        }
        Ok(Keypair {
            secret_key_source: secret_key.unwrap(),
            public_key_source: public_key.unwrap(),
        })
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
pub(crate) fn get_legacy_keypair_from_disk<T: toml_edit::TableLike, SFN: IsTStr, PFN: IsTStr>(
    raw: &str,
    table: &T,
    table_span: Option<std::ops::Range<usize>>,
    new_name: &str,
) -> Result<Keypair<KeyFromDisk<SFN>, KeyFromDisk<PFN>>, Vec<ParseError>> {
    let mut errors = Vec::new();

    const LEGACY_SECRET: &str = "secret_key";
    const LEGACY_PUBLIC: &str = "public_key";

    let legacy_secret = get_as_opt_path_buf(raw, table, table_span.clone(), LEGACY_SECRET)
        .process_parse_result(&mut errors)
        .flatten();
    let legacy_public = get_as_opt_path_buf(raw, table, table_span.clone(), LEGACY_PUBLIC)
        .process_parse_result(&mut errors)
        .flatten();
    let new = get_as_opt_keypair_with_pub_from_disk(raw, table, table_span.clone(), new_name)
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
                table_span.clone(),
                format!("expected key \"{new_name}\""),
            )]);
        }
        (None, Some(_), None) => {
            return Err(vec![ParseError::new(
                raw,
                table_span.clone(),
                format!("expected key \"{LEGACY_SECRET}\""),
            )]);
        }
        (Some(_), None, None) => {
            return Err(vec![ParseError::new(
                raw,
                table_span.clone(),
                format!("expected key \"{LEGACY_PUBLIC}\""),
            )]);
        }

        // conflicting keys
        (None, Some(_), Some(_)) => {
            return Err(vec![ParseError::new(
                raw,
                table_span.clone(),
                format!(
                    "keys \"{LEGACY_PUBLIC}\" and \"{new_name}\" are mutually exclusive and \"{LEGACY_PUBLIC}\" is deprecated"
                ),
            )]);
        }
        (Some(_), None, Some(_)) => {
            return Err(vec![ParseError::new(
                raw,
                table_span.clone(),
                format!(
                    "keys \"{LEGACY_SECRET}\" and \"{new_name}\" are mutually exclusive and \"{LEGACY_SECRET}\" is deprecated"
                ),
            )]);
        }
        (Some(_), Some(_), Some(_)) => {
            return Err(vec![ParseError::new(
                raw,
                table_span.clone(),
                format!(
                    "keys \"{LEGACY_SECRET}\" and \"{LEGACY_PUBLIC}\" (deprecated keypair definition) can not be used together with \"{new_name}\""
                ),
            )]);
        }

        // legacy keypair
        (Some(secret), Some(public), None) => Keypair {
            secret_key_source: KeyFromDisk::<SFN>::new(KeyFromDiskInner::File(secret)),
            public_key_source: KeyFromDisk::<PFN>::new(KeyFromDiskInner::File(public)),
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
    |raw: &str, item: &toml_edit::Item, s: &str| {
        const V1: &str = "1";
        if s == V1 {
            Ok(TomlConfigFileVersion::Version1)
        } else {
            Err(vec![ParseError::new(
                raw,
                item.span(),
                format!("invalid config file version; supported values are \"{V1}\""),
            )])
        }
    }
);
