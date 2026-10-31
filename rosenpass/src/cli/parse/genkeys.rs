use super::{CliGrammar, GenKeysPathsSource};
use crate::{
    cli::types::GenKeysParameters,
    config::{DefaultFileName, PublicPqKeySource, PublicWgKeySource, SecretPqKeySource},
};
use anyhow::{anyhow, bail};
use pest_typed::TypedParser;
use pest_typed_derive::TypedParser;
use std::{
    fmt::{self, Display},
    iter,
    path::PathBuf,
};

/// parser for `gen-keys` subcommand
#[derive(TypedParser)]
#[grammar_inline = r#"
// ===== common =====
separator = _{ "\0" }
path = @{ (!separator ~ ANY)+ }

// ===== rp command =====
rp_genkeys_parameters = { SOI ~ directory_path ~ EOI }
directory_path = { path }

// ===== rosenpass command =====
rosenpass_genkeys_parameters = { SOI ~ genkeys_parameters_inner ~ EOI }
genkeys_parameters_inner = { parameter? ~ (separator ~ parameter)* }

parameter = { secret_key | public_key | force_flag }

force_flag = { "-f" | "--force" }

secret_key = { ("--secret-key" | "--private-key" | "-s") ~ separator ~ sec_path }
public_key = { ("--public-key" | "-p") ~ separator ~ pub_path }

pub_path = { path }
sec_path = { path }
"#]
#[emit_rule_reference]
struct RosenpassParser;

pub fn help<'a>(indent: &'a str, grammar: CliGrammar) -> impl Display + 'a {
    let i = indent; // shorter, save a bit of space in the code
    fmt::from_fn(move |f| match grammar {
        CliGrammar::Rosenpass => writeln!(
            f,
            r#"gen-keys [-s | --secret-key] <FILE> [-p | --public-key] <FILE> [-f | --force]"#
        ),
        CliGrammar::Rp => writeln!(f, r#"genkey <DIRECTORY>"#),
    })
}

/// parse [`super::CliCommand::GenKeys`] from a command line
///
/// - TODO: write unit tests for `rosenpass` and `rp` that they write to the correct files
///   - maybe such tests already exist?
pub fn parse(parameters: &str, grammar: CliGrammar) -> Result<GenKeysParameters, anyhow::Error> {
    // parse parameter
    let rename_rule = |rule: &Rule| -> String {
        match *rule {
            // rp
            Rule::rp_genkeys_parameters => "parameters for the genky subcommand".into(),
            Rule::directory_path => "path to the output directory".into(),
            // rosenpass
            Rule::rosenpass_genkeys_parameters
            | Rule::genkeys_parameters_inner
            | Rule::parameter => "parameters for the gen-key subcommand".into(),
            Rule::force_flag => "--force".into(),
            Rule::secret_key => "--secret-key <FILE_PATH>".into(),
            Rule::public_key => "--public-key <FILE_PATH>".into(),
            Rule::pub_path => "path to the public key file".into(),
            Rule::sec_path => "path to the secret key file".into(),
            // common
            Rule::path => "path to a file or directory".into(),
            Rule::EOI => "end of command line".into(),
            Rule::separator => "end of argument".into(),
        }
    };
    match grammar {
        CliGrammar::Rp => {
            let parameters = RosenpassParser::try_parse::<pairs::rp_genkeys_parameters>(parameters)
                .map_err(|error| {
                    let error = error
                        .renamed_rules(rename_rule)
                        .to_string()
                        .replace('\0', " ");
                    anyhow!(error)
                })?;
            let directory = PathBuf::from(parameters.directory_path().path().span.as_str());
            let pqsk_path = directory.join(SecretPqKeySource::default_file_name());
            let pqpk_path = directory.join(PublicPqKeySource::default_file_name());
            let wgpk_path = directory.join(PublicWgKeySource::default_file_name());

            Ok(GenKeysParameters {
                file_paths: GenKeysPathsSource::Raw {
                    generate_directory: Some(directory),
                    secret_key_file: pqsk_path,
                    public_key_file: pqpk_path,
                    wg_secret_key_file: Some(wgpk_path),
                },
                // rp never overwrites existing keys
                // TODO: should rp get a `--force` flag?
                // https://github.com/rosenpass/rosenpass/issues/1201
                force: false,
            })
        }
        CliGrammar::Rosenpass => {
            let parameters =
                RosenpassParser::try_parse::<pairs::rosenpass_genkeys_parameters>(parameters)
                    .map_err(|error| {
                        let error = error
                            .renamed_rules(rename_rule)
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
                file_paths: crate::cli::GenKeysPathsSource::Raw {
                    // the `rosenpass` CLI grammar assumes that the directory already exists
                    generate_directory: None,

                    secret_key_file: PathBuf::from(secret),
                    public_key_file: PathBuf::from(public),

                    // the `rosenpass` CLI grammar does not create a WG secret key
                    wg_secret_key_file: None,
                },
                force: force.unwrap_or(false),
            })
        }
    }
}
