use super::{CliCommand, FlatCliCommand};
use anyhow::{anyhow, bail};
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;

pub mod exchange;
pub mod exchange_config;
pub mod genkeys;

impl CliCommand {
    /// TODO: doc
    /// TODO: use proper error type instead of [`anyhow::Error`]
    pub fn parse_from_cli(command_line: &str) -> Result<CliCommand, anyhow::Error> {
        // get the subcommand type and its parameters
        let (flat_command, parameters) = get_subcommand(command_line)?;

        // parse the subcommand
        let command = match flat_command {
            FlatCliCommand::ExchangeConfig => {
                CliCommand::ExchangeConfig(exchange_config::parse(parameters)?)
            }
            FlatCliCommand::Exchange => CliCommand::Exchange(exchange::parse(parameters)?),
            // TODO: genconfig
            FlatCliCommand::GenKeys => CliCommand::GenKeys(genkeys::parse(parameters)?),
            _ => todo!("parse all subcommands"),
        };

        //return
        Ok(command)
    }
}

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
command_line = { SOI ~ subcommand ~ separator ~ remainder ~ EOI }
remainder = { ANY+ }

subcommand = {
    subcommand_exchange_config
    | subcommand_exchange
    | subcommand_gen_config
    | subcommand_gen_keys
    | subcommand_validate
    | subcommand_generate_manpage
    | subcommand_generate_shell_completion
    | subcommand_help
}
subcommand_exchange_config = { "exchange-config" }
subcommand_exchange = { "exchange" }
subcommand_gen_config = { "gen-config" }
subcommand_gen_keys=  { "gen-keys" | "keygen" }
subcommand_validate = { "validate" }
subcommand_generate_manpage = { "--generate-manpage" }
subcommand_generate_shell_completion = { "--print-completions" }
subcommand_help = { "help" | "--help" | "-help" }
"#]
#[emit_rule_reference]
pub struct SubCommandTypeParser;

/// - TODO: fetch `--help` if it comes at the end of some command line
/// - TODO: evaluate to Help if no parameter is given
pub fn get_subcommand(command_line: &str) -> Result<(FlatCliCommand, &str), anyhow::Error> {
    let command_line = SubCommandTypeParser::try_parse::<pairs::command_line>(command_line)
        .map_err(|error| {
            let error = error
                .renamed_rules(|rule| match rule.name() {
                    "subcommand" => "a subcommand".into(),
                    "subcommand_exchange_config" => "the subcommand \"exchange-config\"".into(),
                    "subcommand_exchange" => "the subcommand \"exchange\"".into(),
                    name => name.replace("_", " "),
                })
                .to_string()
                .replace('\0', " ");
            anyhow!(error)
        })?;
    let subcommand = command_line.subcommand();
    let remainder = command_line.remainder().span.as_str();
    if subcommand.subcommand_exchange_config().is_some() {
        Ok((FlatCliCommand::ExchangeConfig, remainder))
    } else if subcommand.subcommand_exchange().is_some() {
        Ok((FlatCliCommand::Exchange, remainder))
    } else if subcommand.subcommand_gen_config().is_some() {
        Ok((FlatCliCommand::GenConfig, remainder))
    } else if subcommand.subcommand_gen_keys().is_some() {
        Ok((FlatCliCommand::GenKeys, remainder))
    } else if subcommand.subcommand_validate().is_some() {
        Ok((FlatCliCommand::Validate, remainder))
    } else if subcommand.subcommand_generate_manpage().is_some() {
        Ok((FlatCliCommand::GenerateManpage, remainder))
    } else if subcommand.subcommand_generate_shell_completion().is_some() {
        Ok((FlatCliCommand::GenerateShellCompletion, remainder))
    } else if subcommand.subcommand_help().is_some() {
        Ok((FlatCliCommand::Help, remainder))
    } else {
        bail!("unknown subcommand \"{}\"", subcommand.span.as_str())
    }
}
