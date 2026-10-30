use super::BrokerInterface;
use super::ExchangeConfigParameters;
use crate::config::RosenpassConfig;
use anyhow::{anyhow, bail};
use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;
use std::fmt;
use std::fmt::Display;
use std::path::PathBuf;

#[derive(TypedParser)]
#[grammar_inline = r#"
separator = _{ "\0" }
exchange_config_arguments = { SOI ~ config_path ~ (psk_broker_option)? ~ EOI }

psk_broker_option = {
    psk_broker_spawn
    | psk_broker_path
    | psk_broker_fd
}
psk_broker_spawn = { "--psk-broker-spawn" }
psk_broker_path = { "--psk-broker-path" ~ separator ~ broker_path }
psk_broker_fd = { "--psk-broker-fd" ~ separator ~ file_descriptor }

config_path = { !psk_broker_option ~ path }
path = @{ (!separator ~ ANY)+ }
broker_path = { path }
file_descriptor = @{ (!separator ~ ANY)+ }
"#]
#[emit_rule_reference]
struct Parser;

/// returns the help message for the `rosenpass exchange-config` subcommand
#[rustfmt::skip]
pub fn help<'a>(indent: &'a str) -> impl Display + 'a {
    let i = indent; // shorter, save a bit of space in the code
    fmt::from_fn(move |f| {
        todo!()
    })
}

/// parse [`super::CliCommand::ExchangeConfig`] from a command line
pub fn parse(parameters: &str) -> Result<ExchangeConfigParameters, anyhow::Error> {
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

    let path = PathBuf::from(parameters.config_path().span.as_str());

    let psk_broker_config = parameters
        .psk_broker_option()
        .map(|o| -> anyhow::Result<BrokerInterface> {
            if o.psk_broker_spawn().is_some() {
                Ok(BrokerInterface::SocketPair)
            } else if let Some(path) = o.psk_broker_path() {
                Ok(BrokerInterface::Socket(PathBuf::from(
                    path.broker_path().path().span.as_str(),
                )))
            } else if let Some(fd) = o.psk_broker_fd() {
                Ok(BrokerInterface::FileDescriptor(
                    fd.file_descriptor()
                        .span
                        .as_str()
                        .parse::<i32>()
                        .map_err(|e| anyhow!(e))?,
                ))
            } else {
                bail!(
                    "unexpected PSK broker option: {}",
                    o.span.as_str().replace('\0', " ")
                );
            }
        })
        .transpose()?;

    Ok(ExchangeConfigParameters {
        config: RosenpassConfig::load_from_file(&path)?,
        psk_broker_config,
    })
}
