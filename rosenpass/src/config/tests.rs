#![cfg(test)]

use std::{ffi::OsString, str::FromStr};

use anyhow::anyhow;

use crate::config::validation::ValidationRecipe;

use super::*;

#[test]
fn read_example_config() -> Result<(), anyhow::Error> {
    let filename = OsString::from_str("./Ilkas Config.toml").unwrap();
    let data = std::fs::read(filename).map_err(|err| anyhow!(err))?;
    let data = String::from_utf8(data).map_err(|err| anyhow!(err))?;
    let data = toml_edit::Document::from_str(data.as_str()).map_err(|err| anyhow!(err))?;
    let data = RosenpassConfig::parse_from_toml(data).expect("parsing failed");
    data.0.validate(ValidationRecipe::all());
    Ok(())
}
