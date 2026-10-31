use super::{CliGrammar, GenKeysPathsSource, GenPubKeysParameters};
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
rp_pubkey_parameters = { SOI ~ secret_key_dir ~ separator ~ public_key_dir ~ EOI }
secret_key_dir = { path }
public_key_dir = { path }
"#]
#[emit_rule_reference]
struct RosenpassParser;

pub fn help<'a>(indent: &'a str) -> impl Display + 'a {
    let i = indent; // shorter, save a bit of space in the code
    fmt::from_fn(|f| {
        writeln!(
            f,
            r#"pubkey <SECRET_KEYS_DIRECTORY> <PUBLIC_KEYS_DIRECTORY>"#
        )
    })
}

/// parse [`super::CliCommand::GenPubKeys`] from a command line
pub fn parse(parameters: &str, grammar: CliGrammar) -> Result<GenPubKeysParameters, anyhow::Error> {
    // parse parameter
    let rename_rule = |rule: &Rule| -> String {
        match *rule {
            Rule::rp_pubkey_parameters => "parameters for the subcommand".into(),
            Rule::public_key_dir => "path to the public key directory".into(),
            Rule::secret_key_dir => "path to the secret key directory".into(),
            Rule::path => "path to a directory".into(),
            Rule::EOI => "end of command line".into(),
            Rule::separator => "end of argument".into(),
        }
    };
    match grammar {
        CliGrammar::Rp => {
            let parameters = RosenpassParser::try_parse::<pairs::rp_pubkey_parameters>(parameters)
                .map_err(|error| {
                    let error = error
                        .renamed_rules(rename_rule)
                        .to_string()
                        .replace('\0', " ");
                    anyhow!(error)
                })?;

            Ok(GenPubKeysParameters {
                secret_keys_directory: PathBuf::from(
                    parameters.secret_key_dir().path().span.as_str(),
                ),
                public_keys_directory: PathBuf::from(
                    parameters.public_key_dir().path().span.as_str(),
                ),
            })
        }
        CliGrammar::Rosenpass => {
            bail!(
                r#"The "rosenpass" command does not support this subcommand. Did you mean to call "rp" instead?"#
            );
        }
    }
}
