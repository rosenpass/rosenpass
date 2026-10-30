use crate::{
    config::{PrettyIssueOutput, RosenpassConfig},
    cli::types::GenConfigParameters,
};
use anyhow::{anyhow, bail};
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;
use std::path::PathBuf;

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

/// parse [`super::CliCommand::GenConfig`] from a command line
pub fn parse(parameters: &str) -> Result<GenConfigParameters, anyhow::Error> {
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
