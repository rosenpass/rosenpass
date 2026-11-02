use anyhow::{anyhow, bail};
use pest_typed::TypedParser;
use pest_typed_derive::TypedParser;
use std::{
    fmt::{self, Display},
    iter,
    path::PathBuf,
};

use crate::cli::CliGrammar;

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
validate_arguments = { SOI ~ path ~ ( separator ~ path)* ~ EOI }
path = @{ (!separator ~ ANY)+ }
"#]
#[emit_rule_reference]
struct Parser;

/// returns the help message for the `rosenpass validate` subcommand
// #[rustfmt::skip]
pub fn help<'a>(indent: &'a str, grammar: CliGrammar) -> anyhow::Result<impl Display + 'a> {
    let i = indent; // shorter, save a bit of space in the code
    match grammar {
        CliGrammar::Rosenpass => Ok(fmt::from_fn(move |f| {
            writeln!(f, "validate <FILE>...")?;

            Ok(())
        })),
        CliGrammar::Rp => {
            bail!("this subcommand only exists for the rosenpass tool, not for the rp tool");
        }
    }
}

/// parse [`super::CliCommand::Validate`] from a command line
pub fn parse(parameters: &str, grammar: CliGrammar) -> Result<Vec<PathBuf>, anyhow::Error> {
    match grammar {
        CliGrammar::Rosenpass => (),
        CliGrammar::Rp => {
            bail!("this subcommand only exists for the rosenpass tool, not for the rp tool");
        }
    }
    let parameters =
        Parser::try_parse::<pairs::validate_arguments>(parameters).map_err(|error| {
            let error = error
                .renamed_rules(|rule| match *rule {
                    // TODO: rule renaming does not work:
                    // https://github.com/TheVeryDarkness/pest-typed/issues/4
                    Rule::validate_arguments => "arguments to the subcommand".into(),
                    Rule::path => "path to a configuration file".into(),
                    Rule::EOI => "end of command line".into(),
                    Rule::separator => "end of argument".into(),
                })
                .to_string()
                .replace('\0', " ");
            anyhow!(error)
        })?;
    let (first, following) = parameters.path();
    Ok(iter::once(first)
        .chain(following)
        .map(|p| PathBuf::from(p.span.as_str()))
        .collect::<Vec<PathBuf>>())
}
