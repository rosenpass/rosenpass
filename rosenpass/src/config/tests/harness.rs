//! helper functions for config tests

use super::*;
use crate::config::{
    parse_from_toml::errors::{ParseIssue, ParseWarning, PrettyIssueOutput},
    validate::{
        Error as ValidationError, Issue as ValidationIssue, ValidationRecipe,
        Warning as ValidationWarning,
    },
};
use anyhow::anyhow;
use std::{
    env::current_dir,
    fs::OpenOptions,
    io::Write,
    path::{Path, PathBuf},
    str::FromStr,
};
use toml_edit::DocumentMut;

/// helper function for config tests
///
/// - initializes secret memory policy
/// - prints the current working directory to output (for debugging if test fails)
fn init() -> Result<(), anyhow::Error> {
    // TODO: initialize secret memory?
    // println!("initializing secret memory allocator...");
    // crate::internal::secret_memory::policy::secret_policy_try_use_memfd_secrets();

    let cwd = current_dir()?;
    println!("current working directory: {cwd:?}");

    Ok(())
}

/// reads a TOML file from a file path
///
/// This is a helper function for config tests.
///
/// - reads from `src/config/tests/data/configs/${path}` where `path` is the function's parameter
/// - tries to interpret input as UTF-8 characters
/// - parses TOML into [`toml_edit::Document`]
/// - **returns** the parsed data and the current working directory
pub fn read_toml(path: &Path) -> Result<(toml_edit::Document<String>, PathBuf), anyhow::Error> {
    init()?;
    let path = std::path::Path::new("src/config/tests/data/configs").join(path);
    println!("reading file: {path:?}");
    let data = std::fs::read(path.clone()).map_err(|err| anyhow!(err))?;
    let data = String::from_utf8(data).map_err(|err| anyhow!(err))?;
    println!("parsing TOML...");
    let data = toml_edit::Document::from_str(data.as_str()).map_err(|err| anyhow!(err))?;
    let working_dir = path.parent().unwrap().to_owned();
    println!("working directory of that config file is: {working_dir:?}");
    Ok((data, working_dir))
}

/// TODO: document
/// TODO: no DRY, see `fn read_toml`
pub fn read_toml_mut(path: &Path) -> Result<(toml_edit::DocumentMut, PathBuf), anyhow::Error> {
    init()?;
    let path = std::path::Path::new("src/config/tests/data/configs").join(path);
    println!("reading file: {path:?}");
    let data = std::fs::read(path.clone()).map_err(|err| anyhow!(err))?;
    let data = String::from_utf8(data).map_err(|err| anyhow!(err))?;
    println!("parsing TOML...");
    let data = toml_edit::DocumentMut::from_str(data.as_str()).map_err(|err| anyhow!(err))?;
    let working_dir = path.parent().unwrap().to_owned();
    println!("working directory of that config file is: {working_dir:?}");
    Ok((data, working_dir))
}

/// wrapper around [`RosenpassConfig::parse_from_toml`] printing debug info
///
/// This is a helper function for config tests.
///
/// - parses [`toml_edit::Document`] into a [`RosenpassConfig`] with [`RosenpassConfig::parse_from_toml`]
/// - prints warnings and errors for debugging failed tests
/// - prints a successfully parsed [`RosenpassConfig`] (if successful)
/// - returns the result from [`RosenpassConfig::parse_from_toml`] verbatim
pub fn parse(
    document: toml_edit::Document<String>,
    file_path: &Path,
) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
    println!("parsing `RosenpassConfig` from `toml_edit::Document`...");
    let data = RosenpassConfig::parse_from_toml(&document, file_path);
    match &data {
        Ok((data, warnings)) => {
            println!("successfully parsed this config:");
            println!("{:#?}", data);
            if warnings.is_empty() {
                println!("no warnings occured");
            } else {
                println!("{} warnings occured:", warnings.len());
                for warning in warnings.iter() {
                    anstream::eprintln!("{}", warning.pretty(document.raw()));
                }
            }
        }
        Err(err) => {
            println!("failed parsing a valid `RosenpassConfig`");
            println!("{} issues occured:", err.len());
            for issue in err.iter() {
                anstream::eprintln!("{}", issue.pretty(document.raw()));
            }
        }
    }
    data
}

/// wrapper around [`RosenpassConfig::validate`] printing debug info
///
/// This is a helper function for config tests.
///
/// - call [`RosenpassConfig::validate`]
/// - if successful, prints the returned warnings to stdout
/// - if failed, prints the returned erros to stdout
/// - returns the result from [`RosenpassConfig::validate`] verbatim
pub fn validate(
    config: &RosenpassConfig,
    recipe: ValidationRecipe,
) -> Result<Vec<ValidationWarning>, Vec<ValidationIssue>> {
    println!("validating `RosenpassConfig` with this recipe: {recipe:?}...");
    let result = config.validate(recipe);
    match &result {
        Ok(warnings) => {
            println!("validation was successful");
            if warnings.is_empty() {
                println!("no warnings occured");
            } else {
                println!("{} warnings occured:", warnings.len());
                for warning in warnings.iter() {
                    println!("{}", warning);
                }
            }
        }
        Err(issues) => {
            println!("validation has failed");
            println!("{} issues occured:", issues.len());
            for issue in issues.iter() {
                println!("{}", issue);
            }
        }
    }
    result
}

/// prints sensible debug info for the results of [`RosenpassConfig::validate`]
///
/// This is a helper function for config tests.
///
/// The function goes through the result of [`RosenpassConfig::validate`] and checks that is
/// contains no errors. However, the function does allow very specific errors which are just
/// platform quirks, e.g. if wireguard is not installed.
pub fn assert_validation_succeeded(
    validation_result: Result<Vec<ValidationWarning>, Vec<ValidationIssue>>,
) {
    let issues = match validation_result {
        Ok(warnings) => warnings
            .into_iter()
            .map(ValidationIssue::Warning)
            .collect::<Vec<_>>(),
        Err(issues) => issues,
    };
    for issue in issues.iter() {
        match issue {
            ValidationIssue::Error(err) => match err {
                ValidationError::DefaultWireguardBinaryDoesNotExist
                | ValidationError::DevicesWireguardBinaryDoesNotExist(_, _)
                | ValidationError::PeersWireguardBinaryDoesNotExist(_, _) => {
                    // this is OK because the wireguard binary might not be available on the test setup
                }
                _ => panic!("config validation has errors"),
            },
            ValidationIssue::Warning(_) => {
                // this is OK
            }
        }
    }
    println!(
        "the result of `RosenpassConfig::validate` contains no meaningful errors (missing wg binary errors might be omitted)"
    );
}

/// TODO: doc
pub fn replace_toml_item(doc: &mut DocumentMut, path: &str, replacement: toml_edit::Value) {
    assert!(!path.is_empty());

    // find current value
    let mut current = doc.as_item_mut();
    for segment in path.split('.') {
        assert!(!segment.is_empty(), "invalid path: {path}");
        let next = if current.is_array() || current.is_array_of_tables() {
            let index = segment.parse::<usize>().expect("expected array index");
            current.get_mut(index)
        } else if current.get(segment).is_some() {
            current.get_mut(segment)
        } else {
            None // segment not found
        };
        current = next.unwrap_or_else(|| {
            panic!("can not replace TOML item: key not found: {path} (at {segment})")
        });
    }

    // replace current value
    let original = current
        .as_value_mut()
        .unwrap_or_else(|| panic!("not a TOML value: {path}"));
    let mut replacement = replacement;
    *replacement.decor_mut() = original.decor().clone(); // preserve whitespace and comments
    *original = replacement;
}

/// TODO: doc
fn remove_toml_item(doc: &mut DocumentMut, path: &str) {
    assert!(!path.is_empty());

    // split segments
    let mut segments = path.split('.').collect::<Vec<_>>();
    let last = segments.pop().unwrap();
    let mut current = doc.as_item_mut();

    // navigate to the parent of the item to delete
    for segment in segments {
        assert!(!segment.is_empty(), "invalid path: {path}");
        let next = if current.is_array() || current.is_array_of_tables() {
            let index = segment.parse::<usize>().expect("expected array index");
            current.get_mut(index)
        } else {
            current.get_mut(segment)
        };
        current = next.unwrap_or_else(|| panic!("path not found: {path} (at {segment})"));
    }

    // delete the final item from its parent
    if let Some(table) = current.as_table_like_mut() {
        table
            .remove(last)
            .unwrap_or_else(|| panic!("path not found: {path}"));
    } else if let Some(array) = current.as_array_mut() {
        let index = last
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("expected array index: {last}"));

        if array.get(index).is_none() {
            panic!("path not found: {path}");
        }
        array.remove(index);
    } else if let Some(array) = current.as_array_of_tables_mut() {
        let index = last
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("expected array index: {last}"));

        if array.get(index).is_none() {
            panic!("path not found: {path}");
        }
        array.remove(index);
    } else {
        panic!("not a container: {path}");
    }
}

fn add_toml_item(doc: &mut DocumentMut, path: &str, to_add: toml_edit::Value) {
    assert!(!path.is_empty());

    let mut segments = path.split('.').collect::<Vec<_>>();
    let last = segments.pop().unwrap();
    let mut current = doc.as_item_mut();

    // navigate to the parent of the new item
    for segment in segments {
        assert!(!segment.is_empty(), "invalid path: {path}");
        let next = if current.is_array() || current.is_array_of_tables() {
            let index = segment
                .parse::<usize>()
                .unwrap_or_else(|_| panic!("expected array index: {segment}"));
            current.get_mut(index)
        } else if current.get(segment).is_some() {
            // Avoid creating missing intermediate entries.
            current.get_mut(segment)
        } else {
            None
        };
        current = next.unwrap_or_else(|| panic!("path not found: {path} (at {segment})"));
    }

    // insert into a table or inline table
    if let Some(table) = current.as_table_like_mut() {
        assert!(table.get(last).is_none(), "item already exists: {path}");
        table.insert(last, to_add.into());
    } else if let Some(array) = current.as_array_mut() {
        let index = last
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("expected array index: {last}"));
        assert!(index <= array.len(), "array index out of bounds: {path}");
        array.insert(index, to_add);
    } else {
        panic!("not a container: {path}");
    }
}

/// TODO: this code is dirty, clean it up
#[derive(Clone)]
pub enum PreparedNewValue<'a> {
    TomlValue(&'a toml_edit::Value),
    String(String),
}
impl<'a> From<&'a str> for PreparedNewValue<'a> {
    fn from(value: &str) -> Self {
        Self::String(value.to_string())
    }
}
impl From<PreparedNewValue<'_>> for toml_edit::Value {
    fn from(value: PreparedNewValue) -> Self {
        match value {
            PreparedNewValue::TomlValue(v) => v.clone(),
            PreparedNewValue::String(s) => toml_edit::Value::from(s.to_owned()),
        }
    }
}
/// TODO: doc
pub fn prepare_config_file(
    template_file: &Path,
    destination_file: &Path,
    replacements: Vec<(&str, PreparedNewValue)>,
    deletions: Vec<&str>,
    additions: Vec<(&str, PreparedNewValue)>,
) -> Result<(toml_edit::Document<String>, PathBuf), anyhow::Error> {
    // read template file
    let (mut document, working_directory) = read_toml_mut(template_file)?;

    // run replacements/deletions/additions
    println!("replacing values...");
    for replacement in replacements.iter() {
        replace_toml_item(&mut document, replacement.0, replacement.1.clone().into());
    }
    println!("deleting values...");
    for deletion in deletions.iter() {
        remove_toml_item(&mut document, deletion);
    }
    println!("adding values...");
    for addition in additions.iter() {
        add_toml_item(&mut document, addition.0, addition.1.clone().into());
    }

    // save file to new destination
    // let destination_file = working_directory.join(destination_file);
    println!("saving new config file to: {destination_file:?}");
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(working_directory.join(destination_file))?;
    file.write_all(&document.to_string().into_bytes())?;
    file.flush()?;

    // read the new file back
    println!("reading new config file...");
    read_toml(destination_file)
}

pub(crate) trait ExpectSilent {
    type Output;
    fn expect_silent(self, message: &str) -> Self::Output;
}

impl<T, E> ExpectSilent for Result<T, E> {
    type Output = T;
    fn expect_silent(self, message: &str) -> Self::Output {
        match self {
            Ok(t) => t,
            Err(e) => panic!("{message}"),
        }
    }
}
