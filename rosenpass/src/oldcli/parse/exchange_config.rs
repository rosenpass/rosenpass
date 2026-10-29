use crate::config::{PrettyIssueOutput, RosenpassConfig};
use anyhow::anyhow;
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;
use std::path::PathBuf;

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
exchange_config_arguments = { SOI ~ path ~ EOI }

path = @{ (!separator ~ ANY)+ }
"#]
#[emit_rule_reference]
struct Parser;

/// parse [`super::CliCommand::ExchangeConfig`] from a command line
pub fn parse(parameters: &str) -> Result<RosenpassConfig, anyhow::Error> {
    let parameters =
        Parser::try_parse::<pairs::exchange_config_arguments>(parameters).map_err(|error| {
            let error = error
                .renamed_rules(|rule| match rule.name() {
                    "path" => "path to a configuration file".into(),
                    name => name.into(),
                })
                .to_string()
                .replace('\0', " ");
            anyhow!(error)
        })?;

    let path = PathBuf::from(parameters.path().span.as_str());

    Ok(RosenpassConfig::load_from_file(&path)?)
}
