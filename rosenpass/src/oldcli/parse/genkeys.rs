use crate::{
    config::{PrettyIssueOutput, RosenpassConfig},
    oldcli::types::GenKeysParameters,
};
use anyhow::{anyhow, bail};
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;
use std::{iter, path::PathBuf};

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
genkeys_parameters = { SOI ~ genkeys_parameters_inner ~ EOI }

genkeys_parameters_inner = { parameter? ~ (separator ~ parameter)* }

parameter = { secret_key | public_key | force_flag }

force_flag = { "-f" | "--force" }

secret_key = { ("--secret-key" | "--private-key" | "-s") ~ separator ~ sec_path }
public_key = { ("--public-key" | "-p") ~ separator ~ pub_path }

pub_path = { path }
sec_path = { path }

path = @{ (!separator ~ ANY)+ }
"#]
#[emit_rule_reference]
struct Parser;

/// parse [`super::CliCommand::ExchangeConfig`] from a command line
pub fn parse(parameters: &str) -> Result<GenKeysParameters, anyhow::Error> {
    // parse parameter
    let parameters =
        Parser::try_parse::<pairs::genkeys_parameters>(parameters).map_err(|error| {
            let error = error
                .renamed_rules(|rule| match rule.name() {
                    "genkeys_parameters" | "genkeys_parameters_inner" | "parameter" => {
                        "parameters for the gen-key subcommand".into()
                    }
                    "force_flag" => "--force flag".into(),
                    "secret_key" => "--secret-key parameter".into(),
                    "public_key" => "--public-key parameter".into(),
                    "pub_path" => "path to the public key file".into(),
                    "sec_path" => "path to the secret key file".into(),
                    "path" => "path to a file".into(),
                    name => name.into(),
                })
                .to_string()
                .replace('\0', " ");
            anyhow!(error)
        })?;

    let parameters = parameters.genkeys_parameters_inner().parameter();
    let parameters = iter::once(parameters.0).flatten().chain(parameters.1);

    let mut secret = None;
    let mut public = None;
    let mut force = None;

    for parameter in parameters {
        if parameter.force_flag().is_some() {
            match force {
                None => force = Some(true),
                Some(_) => {
                    bail!("more than one --force flag specified");
                }
            }
        } else if let Some(parameter) = parameter.secret_key() {
            match secret {
                None => secret = Some(parameter.sec_path().path().span.as_str()),
                Some(_) => bail!("more than one secret key file specified"),
            }
        } else if let Some(parameter) = parameter.public_key() {
            match public {
                None => public = Some(parameter.pub_path().path().span.as_str()),
                Some(_) => bail!("more than one public key file specified"),
            }
        } else {
            bail!(
                "unknown parameter \"{}\"",
                parameter.span.as_str().replace('\0', " ")
            )
        }
    }
    // check if everything is set
    let secret = secret.ok_or_else(|| anyhow!("require --secret-key parameter"))?;
    let public = public.ok_or_else(|| anyhow!("require --public-key parameter"))?;

    // return
    Ok(GenKeysParameters {
        file_paths: crate::oldcli::GenKeysPathsSource::Raw {
            secret_key_file: PathBuf::from(secret),
            public_key_file: PathBuf::from(public),
        },
        force: force.unwrap_or(false),
    })
}
