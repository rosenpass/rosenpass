//! helper functions for config tests

use crate::config::{
    PrettyIssueOutput, RosenpassConfig,
    parse_from_toml::errors::{ParseError, ParseIssue, ParseWarning},
    validate::{
        Error as ValidationError, Issue as ValidationIssue, ValidationRecipe,
        Warning as ValidationWarning,
    },
};
use anyhow::anyhow;
use std::{
    path::{Path, PathBuf},
    str::FromStr,
};
use toml_edit::DocumentMut;

/// directory holding the TOML config files used as test data (relative to the crate root)
pub const CONFIGS_DIR: &str = "src/config/tests/data/configs";

/// pseudo file name for in-memory-only configs
pub const IN_MEMORY_FILE_NAME: &str = "in-memory.toml";

/// helper function for config tests
///
/// - initializes secret memory policy
/// - prints the current working directory to output (for debugging if test fails)
fn init() -> Result<(), anyhow::Error> {
    // TODO: initialize secret memory?
    // println!("initializing secret memory allocator...");
    // crate::internal::secret_memory::policy::secret_policy_try_use_memfd_secrets();

    // let cwd = current_dir()?;
    // println!("current working directory: {cwd:?}");

    Ok(())
}

/// reads a TOML file from a file path
///
/// This is a helper function for config tests.
///
/// - reads from `src/config/tests/data/configs/${path}` where `path` is the function's parameter
/// - tries to interpret input as UTF-8 characters
/// - parses TOML into [`toml_edit::Document`]
/// - **returns** the parsed data and the path to the file's parent directory
pub fn read_toml(path: &Path) -> Result<(toml_edit::Document<String>, PathBuf), anyhow::Error> {
    init()?;
    let path = Path::new(CONFIGS_DIR).join(path);
    // read
    println!("reading file: {path:?}");
    let data = std::fs::read(path.clone()).map_err(|err| anyhow!(err))?;
    let data = String::from_utf8(data).map_err(|err| anyhow!(err))?;
    // parse
    let data = toml_edit::Document::from_str(data.as_str()).map_err(|err| anyhow!(err))?;
    let working_dir = path.parent().unwrap().to_owned();
    Ok((data, working_dir))
}

/// TODO: document
/// TODO: no DRY, see `fn read_toml`
pub fn read_toml_mut(path: &Path) -> Result<(toml_edit::DocumentMut, PathBuf), anyhow::Error> {
    init()?;
    let path = Path::new(CONFIGS_DIR).join(path);
    // read
    println!("reading file: {path:?}");
    let data = std::fs::read(path.clone()).map_err(|err| anyhow!(err))?;
    let data = String::from_utf8(data).map_err(|err| anyhow!(err))?;
    // parse
    let data = toml_edit::DocumentMut::from_str(data.as_str()).map_err(|err| anyhow!(err))?;
    let working_dir = path.parent().unwrap().to_owned();
    Ok((data, working_dir))
}

/// parses a [`toml_edit::Document`] from a string
///
/// This is a helper function for config tests.
///
/// - sets a pseudo file path located in [`CONFIGS_DIR`]/[`IN_MEMORY_FILE_NAME`]
pub fn doc_from_str<S: ToString>(
    content: S,
) -> Result<(toml_edit::Document<String>, PathBuf), anyhow::Error> {
    init()?;
    Ok((
        toml_edit::Document::from_str(content.to_string().as_str()).map_err(|err| anyhow!(err))?,
        Path::new(CONFIGS_DIR).join(IN_MEMORY_FILE_NAME),
    ))
}

/// TODO: similar to implementation for parsing CLI, this is not DRY
fn print_parse_result(
    document: &toml_edit::Document<String>,
    data: &Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>>,
) {
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
    println!("parsing...");
    let data = RosenpassConfig::parse_from_toml(&document, file_path);
    print_parse_result(&document, &data);
    data
}

/// wrapper around [`parse`] for TOML documents parsed from a string
///
/// This is a helper function for config tests.
pub fn parse_string<S: ToString>(
    content: S,
) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
    let (document, file_path) = doc_from_str(content).expect("test contains invalid TOML");
    parse(document, &file_path)
}

/// parses a TOML string which is expected to fail parsing
///
/// This is a helper function for config tests.
///
/// - pretty-prints the resulting issues (for debugging failed tests)
/// - **panics** if parsing unexpectedly succeeds
/// - returns the parse issues verbatim
pub fn parse_str_expect_failure<S: ToString>(content: S) -> Vec<ParseIssue> {
    let (document, file_path) = doc_from_str(content).expect("test contains invalid TOML");
    match RosenpassConfig::parse_from_toml(&document, &file_path) {
        Ok((config, warnings)) => {
            println!("{config:#?}");
            panic!("expected parsing to fail, but it succeeded (warnings: {warnings:?})");
        }
        Err(issues) => {
            println!("parsing failed as expected with {} issues:", issues.len());
            for issue in issues.iter() {
                anstream::eprintln!("{}", issue.pretty(document.raw()));
            }
            issues
        }
    }
}

/// all errors within a list of [`ParseIssue`]s
pub fn errors_of(issues: &[ParseIssue]) -> Vec<&ParseError> {
    issues
        .iter()
        .filter_map(|issue| match issue {
            ParseIssue::Error(err) => Some(err),
            ParseIssue::Warning(_) => None,
        })
        .collect()
}

/// asserts that the issues contain, for each `needle`, at least one **error** whose message
/// contains `needle`
pub fn assert_errors_contain(issues: &[ParseIssue], expected: &[&str]) {
    let messages: Vec<&str> = errors_of(issues)
        .iter()
        .map(|err| err.message.as_str())
        .collect();
    for needle in expected {
        assert!(
            messages.iter().any(|msg| msg.contains(needle)),
            "expected an error containing {needle:?}, but the errors are: {messages:#?}"
        );
    }
}

/// asserts that parsing `content` fails and that the errors contain all `expected` substrings
///
/// This is a helper function for config tests.
pub fn assert_parse_str_fails_with<S: ToString>(content: S, expected: &[&str]) -> Vec<ParseIssue> {
    let issues = parse_str_expect_failure(content);
    assert!(
        !errors_of(&issues).is_empty(),
        "expected at least one error"
    );
    assert_errors_contain(&issues, expected);
    issues
}

/// wrapper around [`RosenpassConfig::validate`] printing debug info
///
/// This is a helper function for config tests.
///
/// - call [`RosenpassConfig::validate`]
/// - if successful, prints the returned warnings to stdout
/// - if failed, prints the returned erros to stdout
/// - returns the result from [`RosenpassConfig::validate`] verbatim
///
/// - TODO: use this once `RosenpassConfig::validate` is implemented
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
///
/// - TODO: use this once `RosenpassConfig::validate` is implemented
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

/// a new value to be placed into a TOML document via [`prepare_config`]
#[derive(Clone)]
pub enum PreparedNewValue<'a> {
    /// a ready [`toml_edit::Value`]
    TomlValue(&'a toml_edit::Value),
    /// plain string (becomes a TOML string)
    String(String),
}
impl<'a> From<&'a str> for PreparedNewValue<'a> {
    fn from(value: &'a str) -> Self {
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

/// applies mutations to a TOML template file
///
/// This is a helper function for config tests.
///
/// - reads the template from [`CONFIGS_DIR`]
/// - applies replacements, deletions and additions in this order
/// - **returns** the mutated document and the working directory of the template file
fn mutate_template(
    template_file: &Path,
    replacements: Vec<(&str, PreparedNewValue)>,
    deletions: Vec<&str>,
    additions: Vec<(&str, PreparedNewValue)>,
) -> Result<(toml_edit::DocumentMut, PathBuf), anyhow::Error> {
    let (mut document, working_directory) = read_toml_mut(template_file)?;
    for (path, replacement) in replacements {
        replace_toml_item(&mut document, path, replacement.into());
    }
    for path in deletions {
        remove_toml_item(&mut document, path);
    }
    for (path, addition) in additions {
        add_toml_item(&mut document, path, addition.into());
    }
    Ok((document, working_directory))
}

/// prepares a config file in memory by mutating a template file
///
/// This is a helper function for config tests.
pub fn prepare_config(
    template_file: &Path,
    replacements: Vec<(&str, PreparedNewValue)>,
    deletions: Vec<&str>,
    additions: Vec<(&str, PreparedNewValue)>,
) -> Result<(toml_edit::Document<String>, PathBuf), anyhow::Error> {
    let (document, working_directory) =
        mutate_template(template_file, replacements, deletions, additions)?;
    // round-trip through the string representation to get an immutable document with fresh spans
    let document =
        toml_edit::Document::from_str(&document.to_string()).map_err(|err| anyhow!(err))?;
    let file_path = working_directory.join(template_file);
    Ok((document, file_path))
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
            Err(_e) => panic!("{message}"),
        }
    }
}
