#![cfg(test)]

use std::{env::current_dir, ffi::OsString, str::FromStr};

use anyhow::anyhow;

use crate::config::validation::ValidationRecipe;

use super::*;

#[test]
fn read_example_config() -> Result<(), anyhow::Error> {
    crate::internal::secret_memory::policy::secret_policy_try_use_memfd_secrets();

    let cwd = current_dir()?;
    eprintln!("cwd: {cwd:?}");
    println!("reading file...");
    let filename = OsString::from_str("../Ilkas Config.toml").unwrap();
    let data = std::fs::read(filename).map_err(|err| anyhow!(err))?;
    let data = String::from_utf8(data).map_err(|err| anyhow!(err))?;
    println!("reading TOML...");
    let data = toml_edit::Document::from_str(data.as_str()).map_err(|err| anyhow!(err))?;

    println!("parsing...");
    let data = RosenpassConfig::parse_from_toml(data).expect("parsing failed");
    println!("printing...");
    println!("{:#?}", data.0);

    println!("validating...");
    let issues = data.0.validate(ValidationRecipe::all());
    println!("issues:");
    match issues {
        Ok(warnings) => {
            for warning in warnings.iter() {
                println!("{}", warning)
            }
        }
        Err(issues) => {
            for issue in issues.iter() {
                println!("{}", issue)
            }
        }
    }
    todo!("check output of RosenpassConfig::validate()");

    Ok(())
}
