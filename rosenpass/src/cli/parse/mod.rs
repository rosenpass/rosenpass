//! TODO: rustfmt silently gives up on this file
use crate::{app_server::AppServerTest, cli::types::GenConfigParameters};

use super::{
    BrokerInterface, CliCommand, ExchangeConfigParameters, FlatCliCommand, GenKeysParameters,
    GenKeysPathsSource,
};
use anyhow::{anyhow, bail};
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;

pub mod exchange;
pub mod exchange_config;
pub mod generate_config;
pub mod generate_manpage;
pub mod generate_shell_completion;
pub mod genkeys;
pub mod test;
pub mod validate;

#[derive(TypedParser)]
#[grammar = "cli/parse/subcommand.pest"]
#[emit_rule_reference]
pub struct SubCommandTypeParser;

/// - TODO: evaluate to Help if no parameter is given
impl CliCommand {
    pub fn parse_and_run_from_env(test_helpers: Option<AppServerTest>) -> anyhow::Result<()> {
        let command = Self::parse_from_env()?;
        command.run(test_helpers)
    }

    pub fn parse_from_env() -> anyhow::Result<CliCommand> {
        let args: String = std::env::args().collect::<Vec<_>>().join("\0");
        CliCommand::parse(args.as_str())
    }

    /// TODO: doc
    /// TODO: use proper error type instead of [`anyhow::Error`]
    pub fn parse(command_line: &str) -> Result<CliCommand, anyhow::Error> {
        // remove program name
        // TODO: use that program name in help output?
        let command_line = command_line
            .split('\0')
            .skip(1)
            .collect::<Vec<_>>()
            .join("\0");
        let command_line = command_line.as_str();

        // parse with `pest_typed`
        let command_line = SubCommandTypeParser::try_parse::<pairs::command_line>(command_line)
            .map_err(|error| {
                let error = error
                    .renamed_rules(|rule| match rule.name() {
                        "subcommand" => "a subcommand".into(),
                        "subcommand_exchange_config" => "the subcommand \"exchange-config\"".into(),
                        "subcommand_exchange" => "the subcommand \"exchange\"".into(),
                        // TODO: rename all rules
                        name => name.replace("_", " "),
                    })
                    .to_string()
                    .replace('\0', " ");
                anyhow!(error)
            })?;
        let subcommand = command_line.subcommand();

        let subcommand =
        // parse complicated "help" subcommand
        if let Some(subcommand_help) = subcommand.subcommand_help() {
            let subcommand = [
                subcommand_help.subcommand_not_help().0,
                subcommand_help.subcommand_not_help().1,
            ]
            .iter()
              .flatten().next().map(|sub| ->Result<FlatCliCommand,anyhow::Error> {
                 let sub = if sub.subcommand_exchange_config().is_some() {
                    FlatCliCommand::ExchangeConfig
                 }
                else if sub.subcommand_exchange().is_some() {
                    FlatCliCommand::Exchange
                }
                else{
                    bail!("unknown subcommand \"{}\"", sub.span.as_str().replace('\0'," "))    
                };
                Ok(sub)
            }).transpose()?;
            CliCommand::Help(subcommand)
        }
        // parse all other subcommands
        else if let Some(subcommand) = subcommand.subcommand_normal(){
            let remainder = subcommand.argument().iter().map(|a|a.span.as_str()).collect::<Vec<_>>().join("\0");
            let remainder = remainder.as_str();

              let subcommand = subcommand.subcommand_not_help();

            if subcommand.subcommand_exchange_config().is_some() {
                CliCommand::ExchangeConfig(exchange_config::parse(remainder)?)
            } else if subcommand.subcommand_exchange().is_some() {
                CliCommand::Exchange(exchange::parse(remainder)?)
            } else if subcommand.subcommand_gen_config().is_some() {
                CliCommand::GenConfig(generate_config::parse(remainder)?)
            } else if subcommand.subcommand_gen_keys().is_some() {
                CliCommand::GenKeys(genkeys::parse(remainder)?)
            } else if subcommand.subcommand_validate().is_some() {
                CliCommand::Validate(validate::parse(remainder)?)
            } else if subcommand.subcommand_generate_manpage().is_some() {
                CliCommand::GenerateManpage(generate_manpage::parse(remainder)?)
            } else if subcommand.subcommand_generate_shell_completion().is_some() {
                bail!("shell completion is not yet implemented"); // TODO: implement shell completion
                // CliCommand::GenerateShellCompletion(generate_shell_completion::parse(remainder)?)
            } else {
                bail!("unknown subcommand \"{}\"", subcommand.span.as_str().replace('\0'," "))
            }
        }else {
            bail!("unknown subcommand \"{}\"", subcommand.span.as_str().replace('\0'," "))
        };
        Ok(subcommand)
    }
}
