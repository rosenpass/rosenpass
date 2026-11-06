use crate::{
    cli::{CliGrammar, types::GenConfigParameters},
    config::{PrettyIssueOutput, RosenpassConfig},
};
use anyhow::{anyhow, bail};
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;
use std::{
    fmt::{self, Display},
    path::PathBuf,
};

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
generate_config_arguments = { SOI ~ (path_first | force_first) ~ EOI }

path_first = { path ~ (separator ~ force)? }
force_first = { (force ~ separator)? ~ path }


path = @{ !force ~ (!separator ~ ANY)+ }
force = @{ "--force" | "-f" }
"#]
#[emit_rule_reference]
struct Parser;

/// returns the help message for the `rosenpass gen-config` subcommand
// #[rustfmt::skip]
pub fn help<'a>(indent: &'a str, grammar: CliGrammar) -> anyhow::Result<impl Display + 'a> {
    let i = indent; // shorter, save a bit of space in the code
    match grammar {
        CliGrammar::Rosenpass => Ok(fmt::from_fn(move |f| {
            writeln!(f, "generate-config <FILE> [-f | --force]")?;
            Ok(())
        })),
        CliGrammar::Rp => {
            bail!("this subcommand only exists for the rosenpass tool, not for the rp tool")
        }
    }
}

/// parse [`super::CliCommand::GenConfig`] from a command line
pub fn parse(parameters: &str, grammar: CliGrammar) -> Result<GenConfigParameters, anyhow::Error> {
    match grammar {
        CliGrammar::Rosenpass => (),
        CliGrammar::Rp => {
            bail!("this subcommand only exists for the rosenpass tool, not for the rp tool");
        }
    }
    let parameters =
        Parser::try_parse::<pairs::generate_config_arguments>(parameters).map_err(|error| {
            let error = error
                .renamed_rules(|rule| match *rule {
                    // TODO: rule renaming does not work:
                    // https://github.com/TheVeryDarkness/pest-typed/issues/4
                    Rule::generate_config_arguments | Rule::path_first | Rule::force_first => {
                        "arguments to the subcommand".into()
                    }
                    Rule::path => "output path for the generated configuration file".into(),
                    Rule::force => "force flag -f or --f".into(),
                    Rule::EOI => "end of command line".into(),
                    Rule::separator => "end of argument".into(),
                })
                .to_string()
                .replace('\0', " ");
            anyhow!(error)
        })?;
    let (path, force) = if let Some(parameters) = parameters.path_first() {
        (
            parameters.path().span.as_str(),
            parameters.force().is_some(),
        )
    } else if let Some(parameters) = parameters.force_first() {
        (
            parameters.path().span.as_str(),
            parameters.force().is_some(),
        )
    } else {
        bail!(
            "unexpected parse result: {}",
            parameters.span.as_str().replace('\0', " ")
        );
    };

    Ok(GenConfigParameters {
        config_file: PathBuf::from(path),
        force,
    })
}
