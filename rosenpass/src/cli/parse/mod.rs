//! TODO: rustfmt silently gives up on this file
use super::{
    BrokerInterface, CliCommand, CliGrammar, ExchangeConfigParameters, FlatCliCommand,
    GenKeysParameters, GenKeysPathsSource, GenPubKeysParameters,
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
pub mod genpubkeys;
pub mod test;
pub mod validate;

#[derive(TypedParser)]
#[grammar = "cli/parse/subcommand.pest"]
#[emit_rule_reference]
pub struct SubCommandTypeParser;

fn rename_rules(rule: &Rule) -> String {
    match *rule {
        Rule::tool_name => "the tool's name".into(),
        Rule::command_line => "command line".into(),

        Rule::subcommand | Rule::subcommand_normal | Rule::subcommand_not_help => {
            "a subcommand".into()
        }
        Rule::subcommand_help => "the subcommand \"--help\"".into(),
        Rule::subcommand_exchange_config => "the subcommand \"exchange-config\"".into(),
        Rule::subcommand_exchange => "the subcommand \"exchange\"".into(),
        Rule::subcommand_gen_config => "the subcommand \"gen-config\"".into(),
        // TODO: rename all rules
        name => name.name().into(),
    }
}

/// - TODO: evaluate to Help if no parameter is given
impl CliCommand {
    pub fn parse_from_env(grammar: CliGrammar) -> anyhow::Result<(CliCommand, String)> {
        let args: String = std::env::args().collect::<Vec<_>>().join("\0");
        CliCommand::parse(args.as_str(), grammar)
    }

    /// parses a command line and returns the [`CliCommand`] together with the tool name
    ///
    /// - TODO: doc
    /// - TODO: use proper error type instead of [`anyhow::Error`]
    /// - TODO: do not return the `tool_name` in the tuple but as part of `CliCommand` ?
    /// - TODO: write unit tests for `rp` grammar
    /// - TODO: write unit tests for `GenPubkeys`
    pub fn parse(
        command_line: &str,
        grammar: CliGrammar,
    ) -> Result<(CliCommand, String), anyhow::Error> {
        // parse with `pest_typed`
        let command_line = SubCommandTypeParser::try_parse::<pairs::command_line>(command_line)
            .map_err(|error| {
                let error = error
                    .renamed_rules(rename_rules)
                    .to_string()
                    .replace('\0', " ");
                anyhow!(error)
            })?;
        let tool_name = command_line.tool_name().span.as_str().to_string();
        let subcommand = command_line.subcommand();

        let subcommand = subcommand
            .map(|subcommand| -> anyhow::Result<CliCommand> {
                // parse complicated "help" subcommand
                if let Some(subcommand_help) = subcommand.subcommand_help() {
                    let subcommand = [
                        subcommand_help.subcommand_not_help().0,
                        subcommand_help.subcommand_not_help().1,
                    ]
                    .iter()
                    .flatten()
                    .next()
                    .map(|sub| -> Result<FlatCliCommand, anyhow::Error> {
                        let sub = if sub.subcommand_exchange_config().is_some() {
                            FlatCliCommand::ExchangeConfig
                        } else if sub.subcommand_exchange().is_some() {
                            FlatCliCommand::Exchange
                        } else if sub.subcommand_gen_config().is_some() {
                            FlatCliCommand::GenConfig
                        } else if sub.subcommand_gen_keys().is_some() {
                            FlatCliCommand::GenKeys
                        } else if sub.subcommand_gen_pubkeys().is_some() {
                            FlatCliCommand::GenPubKeys
                        } else if sub.subcommand_validate().is_some() {
                            FlatCliCommand::Validate
                        } else if sub.subcommand_generate_manpage().is_some() {
                            FlatCliCommand::GenerateManpage
                        } else if sub.subcommand_generate_shell_completion().is_some() {
                            FlatCliCommand::GenerateShellCompletion
                        } else {
                            bail!(
                                "unknown subcommand \"{}\"",
                                sub.span.as_str().replace('\0', " ")
                            )
                        };
                        Ok(sub)
                    })
                    .transpose()?;
                    Ok(CliCommand::Help((subcommand, grammar)))
                }
                // parse all other subcommands
                else if let Some(subcommand) = subcommand.subcommand_normal() {
                    let remainder = subcommand
                        .argument()
                        .iter()
                        .map(|a| a.span.as_str())
                        .collect::<Vec<_>>()
                        .join("\0");
                    let remainder = remainder.as_str();

                    let subcommand = subcommand.subcommand_not_help();

                    if subcommand.subcommand_exchange_config().is_some() {
                        Ok(CliCommand::ExchangeConfig(exchange_config::parse(
                            remainder, grammar,
                        )?))
                    } else if subcommand.subcommand_exchange().is_some() {
                        Ok(CliCommand::Exchange(exchange::parse(remainder, grammar)?))
                    } else if subcommand.subcommand_gen_config().is_some() {
                        Ok(CliCommand::GenConfig(generate_config::parse(
                            remainder, grammar,
                        )?))
                    } else if subcommand.subcommand_gen_keys().is_some() {
                        Ok(CliCommand::GenKeys(genkeys::parse(remainder, grammar)?))
                    } else if subcommand.subcommand_gen_pubkeys().is_some() {
                        Ok(CliCommand::GenPubKeys(genpubkeys::parse(
                            remainder, grammar,
                        )?))
                    } else if subcommand.subcommand_validate().is_some() {
                        Ok(CliCommand::Validate(validate::parse(remainder, grammar)?))
                    } else if subcommand.subcommand_generate_manpage().is_some() {
                        Ok(CliCommand::GenerateManpage(generate_manpage::parse(
                            remainder, grammar,
                        )?))
                    } else if subcommand.subcommand_generate_shell_completion().is_some() {
                        bail!("shell completion is not yet implemented"); // TODO: implement shell completion
                    // CliCommand::GenerateShellCompletion(generate_shell_completion::parse(remainder)?)
                    } else {
                        bail!(
                            "unknown subcommand \"{}\"",
                            subcommand.span.as_str().replace('\0', " ")
                        )
                    }
                } else {
                    bail!(
                        "unknown subcommand \"{}\"",
                        subcommand.span.as_str().replace('\0', " ")
                    )
                }
            })
            .transpose()?
            .unwrap_or(CliCommand::Help((None, grammar))); // no subcommand given --> show help
        Ok((subcommand, tool_name))
    }
}
