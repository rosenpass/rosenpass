use log::LevelFilter;
use toml_edit::Table;

use super::super::{CryptoAlgorithmsChoice, FlatDeviceManagedByChoice};
use super::errors::ParseError;

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
        pub fn $fn_name<'a>(
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
        pub fn $opt_fn_name<'a>(
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
