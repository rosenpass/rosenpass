#![cfg(test)]

use super::*;
use crate::config::{
    parse_from_toml::errors::{ParseIssue, ParseWarning},
    validation::Error as ValidationError,
    validation::Issue as ValidationIssue,
    validation::ValidationRecipe,
    validation::Warning as ValidationWarning,
};
use anyhow::anyhow;
use std::{env::current_dir, path::PathBuf, str::FromStr};

/// helper function for config tests
///
/// - initializes secret memory policy
/// - prints the current working directory to output (for debugging if test fails)
fn init() -> Result<(), anyhow::Error> {
    println!("initializing secret memory allocator...");
    crate::internal::secret_memory::policy::secret_policy_try_use_memfd_secrets();

    let cwd = current_dir()?;
    println!("current working directory: {cwd:?}");

    Ok(())
}
/// helper function for config tests
///
/// - reads from `src/config/tests/data/configs/${path}` where `path` is the function's parameter
/// - tries to interpret input as UTF-8 characters
/// - parses TOML into [`toml_edit::Document`]
fn read_toml(path: &str) -> Result<(toml_edit::Document<String>, PathBuf), anyhow::Error> {
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
/// helper function for config tests
///
/// A simple wrapper around [`RosenpassConfig::parse_from_toml`] which adds some debug printing.
/// - parses [`toml_edit::Document`] into a [`RosenpassConfig`] with [`RosenpassConfig::parse_from_toml`]
/// - prints warnings and errors for debugging failed tests
/// - prints a successfully parsed [`RosenpassConfig`] (if successful)
/// - returns the result from [`RosenpassConfig::parse_from_toml`] verbatim
fn parse(
    document: toml_edit::Document<String>,
    working_directory: &PathBuf,
) -> Result<(RosenpassConfig, Vec<ParseWarning>), Vec<ParseIssue>> {
    println!("parsing `RosenpassConfig` from `toml_edit::Document`...");
    let data = RosenpassConfig::parse_from_toml(document, working_directory);
    match &data {
        Ok(ok) => {
            println!("successfully parsed this config:");
            println!("{:#?}", ok.0);
            if ok.1.is_empty() {
                println!("no warnings occured");
            } else {
                println!("{} warnings occured:", ok.1.len());
                for warning in ok.1.iter() {
                    println!("{}", warning);
                }
            }
        }
        Err(err) => {
            println!("failed parsing a valid `RosenpassConfig`");
            println!("{} issues occured:", err.len());
            for issue in err.iter() {
                println!("{}", issue);
            }
        }
    }
    data
}
/// helper function for config tests
///
/// wrapper around [`RosenpassConfig::validate`] which add some debug printing.
/// - call [`RosenpassConfig::validate`]
/// - if successful, prints the returned warnings to stdout
/// - if failed, prints the returned erros to stdout
/// - returns the result from [`RosenpassConfig::validate`] verbatim
fn validate(
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
#[test]
fn read_full_non_agile_config() {
    let (config, working_dir) = read_toml("full-non-agile.toml").unwrap();
    let (config, parse_warnings) = parse(config, &working_dir).expect("parser returned errors");
    assert!(parse_warnings.is_empty(), "parser returned warnings");
    let warnings = validate(&config, ValidationRecipe::all()).expect("validation returned errors");
    assert!(warnings.is_empty(), "validation returned warnings");
}
#[test]
fn read_full_agile_config() -> Result<(), anyhow::Error> {
    let data = read_toml("full-agile.toml")?;

    todo!("write test");
    Ok(())
}
