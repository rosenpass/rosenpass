use std::str::FromStr;

use crate::config::{HashAlgorithmChoice, KemAlgorithmChoice, SymmetricCipherChoice};
use crate::protocol::ProtocolVersion;

use super::super::{AsymmetricCipherType, CryptoAlgorithmsChoice, FlatDeviceManagedByChoice};
use super::errors::ParseError;
use log::LevelFilter;
use serde::Deserialize;
use serde::de::value::Error as SerdeError;
use serde::de::value::StrDeserializer;

/// an be used on the output of `get_as_*()` if `let mut errors: Parse<Error> = Vec::new();` has been defined
macro_rules! process_result {
    ($errors: expr, $result: expr) => {
        $result.map(|v| Some(v)).unwrap_or_else(|err| {
            $errors.push(err);
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
        pub fn $fn_name<'a, T: toml_edit::TableLike>(
            raw: &'a str,
            table: &'a T,
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
        pub fn $opt_fn_name<'a, T: toml_edit::TableLike>(
            raw: &'a str,
            table: &'a T,
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
get_as_type_generator!(
    get_as_asymmetric_cipher_type,
    get_as_opt_asymmetric_cipher_type,
    AsymmetricCipherType,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        // let deserializer = serde::de::value::StrDeserializer::new(s);
        // AsymmetricCipherType::deserialize(deserializer)
        <AsymmetricCipherType as Deserialize>::deserialize(StrDeserializer::<SerdeError>::new(s))
            .map_err(|err| ParseError::new(raw, item.span(), err.to_string()))
    }
);
get_as_type_generator!(
    get_as_path_buf,
    get_as_opt_path_buf,
    std::path::PathBuf,
    as_str,
    |raw: &str, item: &toml_edit::Item, s: &str| {
        std::path::PathBuf::from_str(s)
            .map_err(|err| ParseError::new(raw, item.span(), err.to_string()))
    }
);
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
        let error_message =
            "invalid cryptographic algorithm choice, see <TODO> for valid options".to_string();
        let error = ParseError::new(raw, item.span(), error_message.clone());
        let s = s.to_lowercase();
        let parts = s.split("-").collect::<Vec<_>>();
        if parts.len() != 4 {
            return Err(ParseError::new(raw, item.span(), error_message));
        }
        let asymmetric_cipher = <AsymmetricCipherType as Deserialize>::deserialize(
            StrDeserializer::<SerdeError>::new(parts[0]),
        )
        .map_err(|err| error.clone())?;
        let kem = <KemAlgorithmChoice as Deserialize>::deserialize(
            StrDeserializer::<SerdeError>::new(parts[1]),
        )
        .map_err(|err| error.clone())?;
        let symmetric_cipher = <SymmetricCipherChoice as Deserialize>::deserialize(
            StrDeserializer::<SerdeError>::new(parts[2]),
        )
        .map_err(|err| error.clone())?;
        let hash = <HashAlgorithmChoice as Deserialize>::deserialize(
            StrDeserializer::<SerdeError>::new(parts[3]),
        )
        .map_err(|err| error.clone())?;
        Ok(CryptoAlgorithmsChoice {
            asymmetric_cipher,
            kem,
            symmetric_cipher,
            hash,
        })
    }
);

get_as_type_generator!(
    get_as_array,
    get_as_opt_array,
    &'a toml_edit::Array,
    as_array,
    |_, _, list: &'a toml_edit::Array| Ok(list)
);
get_as_type_generator!(
    get_as_inline_table,
    get_as_opt_inline_table,
    &'a toml_edit::InlineTable,
    as_inline_table,
    |_, _, tab: &'a toml_edit::InlineTable| Ok(tab)
);
get_as_type_generator!(
    get_as_vec_string,
    get_as_opt_vec_string,
    Vec<String>,
    as_array,
    |raw: &'a str, item: &'a toml_edit::Item, array: &'a toml_edit::Array| {
        array
            .iter()
            .map(|item| -> Result<String, ParseError> {
                item.as_str().map(|s| s.to_string()).ok_or_else(|| {
                    ParseError::new(raw, item.span(), "expected array of strings".to_string())
                })
            })
            .collect::<Result<_, _>>()
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
            Err(ParseError::new(
                raw,
                item.span(),
                format!("invalid protocol version, supported values: v02, v03"),
            ))
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
            .map_err(|err| ParseError::new(raw, item.span(), err.to_string()))
    }
);
