//! TODO: doc (add proper `README.md here`)
//!
//! TODO: parse new format
//! TODO: parse rp format
//! TODO: parse config subcommand (separate module)
//!

// TODO: use sth like this in clap
// #[derive(Subcommand)]
// enum Command {
//     Exchange {
//         #[arg(
//             trailing_var_arg = true,
//             allow_hyphen_values = true
//         )]
//         syntax: Vec<OsString>,
//     },
// }

// TODO: process_parse_result should be moved to common module

#[cfg(feature = "experiment_api")]
use super::ApiConfig;
use crate::{
    config::Verbosity,
    config::{
        ConfigSource, ConfigSourceCli, KeyFromDiskInner, NewFromInner, PqKeypairSource,
        PublicPqKeySource, RosenpassConfig, SecretPqKeySource,
        parse_from_toml::util::{GuaranteedUnwrap, ProcessParseResult},
    },
    protocol::ProtocolVersion,
};
use std::{net::SocketAddr, path::PathBuf, str::FromStr};

pub mod errors;
pub use errors::{ParseError, ParseIssue, ParseResult, ParseWarning};
use errors::{ProcessParseResult2, declare_issues, return_on_error};

pub(crate) mod util;
use util::parse_peer;

// use pest::Parser;
// use pest_derive::Parser;
// #[derive(Parser)]
// #[grammar = "config/parse_from_cli/rosenpass.pest"]
// struct RosenpassParser;

use pest_typed::{RuleType, TypedParser};
use pest_typed_derive::TypedParser;

#[derive(TypedParser)]
#[grammar = "config/parse_from_cli/exchange.pest"]
#[emit_rule_reference]
struct RosenpassParser;

// TODO: use in main
// let input = std::env::args().skip(TODO).collect::<Vec<_>>().join("\0");

impl RosenpassConfig {
    pub fn parse_from_cli(full_line: &str) -> ParseResult<RosenpassConfig> {
        declare_issues!(errors, warnings);

        let parsed = RosenpassParser::try_parse::<pairs::command_line>(full_line);
        let parsed = match parsed {
            Ok(parsed) => parsed,
            Err(error) => {
                let error = (*error)
                    .renamed_rules(|rule| match rule.name() {
                        "ip_address" => "an IP address".into(),
                        "cidr" => "a CIDR prefix".into(),
                        "peer" => "a peer configuration".into(),
                        "own_config" => "own configuration".into(),
                        // TODO: more renames
                        name => name.replace('_', " "),
                    })
                    .with_path("command line");
                let error = error.to_string().replace('\0', " ");
                return Err(vec![ParseIssue::Error(ParseError::new(
                    None,
                    full_line,
                    errors::ParseProblemError::InvalidCommandLineSyntax(error),
                ))]);
            }
        };

        // our own config
        let own_config = parsed.exchange_body().own_config();
        let our_secret_key = {
            let raw = own_config.own_secret_key().path();
            let transformed = PathBuf::from(raw.span.as_str());
            (raw, transformed)
        };
        let our_public_key = {
            let raw = own_config.own_public_key().path();
            let transformed = PathBuf::from(raw.span.as_str());
            (raw, transformed)
        };
        let listen_addresses = {
            let raw = own_config.listen();
            let transformed = raw
                .iter()
                .map(|l| {
                    let s = l.socket_address().span.as_str();
                    SocketAddr::from_str(s).map_err(|e| {
                        ParseError::new(
                            None,
                            full_line,
                            errors::ParseProblemError::InvalidSocketAddr(s.to_string()),
                        )
                    })
                })
                .collect::<Vec<_>>()
                .process_parse_result(&mut errors);
            (raw, transformed)
        };
        let verbosity = {
            own_config
                .verbosity()
                .map(|raw| {
                    if raw.verbosity_verbose().is_some() {
                        Verbosity::Verbose
                    } else if raw.verbosity_quiet().is_some() {
                        Verbosity::Quiet
                    } else {
                        panic!("unexpected verbosity");
                    }
                })
                .unwrap_or_default()
        };

        let peers = parsed
            .exchange_body()
            .peer()
            .iter()
            .enumerate()
            .filter_map(|(idx, peer)| {
                parse_peer(peer, idx).process_parse_result(&mut errors, &mut warnings)
            })
            .collect::<Vec<_>>();

        // TODO: devices(?)

        return_on_error!(errors, warnings);

        // parsed from
        let parsed_from = ConfigSource::CommandLineArguments(ConfigSourceCli {
            full_command_line: full_line.to_string(),
            full_command_line_human_readable: full_line.replace('\0', " "),
            warnings: warnings.clone(),
        });

        Ok((
            RosenpassConfig {
                our_listen_addresses: listen_addresses.1.guaranteed_unwrap(),
                verbosity,
                our_keypair: PqKeypairSource {
                    secret_key_source: SecretPqKeySource::new(KeyFromDiskInner::File(
                        our_secret_key.1,
                    )),
                    public_key_source: PublicPqKeySource::new(KeyFromDiskInner::File(
                        our_public_key.1,
                    )),
                },
                // TODO: this is the default, maybe read it from CLI?
                supported_protocol_versions: ProtocolVersion::all_supported_by_default(),

                // TODO: read experimental API flags from CLI
                #[cfg(feature = "experiment_api")]
                api: ApiConfig::new_empty(),

                wireguard_devices: vec![],
                peers,
                parsed_from,
            },
            warnings,
        ))
        // let parsed = RosenpassParser::parse(Rule::command_line, complete_line);
        // if let Err(error) = parsed.clone() {
        //     // TODO: produce a proper error
        //     let complete_line = complete_line.replace('\0', " ");
        //     eprintln!("error occured");
        //     let column = match error.line_col {
        //         pest::error::LineColLocation::Pos((line, column)) => {
        //             eprintln!("exactly at line {line}, columns {column}");
        //             column
        //         }
        //         pest::error::LineColLocation::Span((line, column), _) => {
        //             eprintln!("starting at line {line}, columns {column}");
        //             column
        //         }
        //     };
        //     eprintln!("{complete_line}");
        //     eprintln!("{}^", " ".repeat(column.saturating_sub(1)));
        //     eprintln!("error variant: {}", error.variant);
        // };
        //
        // let mut command_line = parsed
        //     // due to above Err match
        //     .ok()
        //     .guaranteed_unwrap()
        //     // get "command_line"
        //     .next()
        //     .unwrap()
        //     .into_inner();
        // println!("command_line: {command_line:?}");
        // let exchange_body = command_line.next().guaranteed_unwrap();
        // exchange_body.as_
        // match exchange_body.as_rule() {
        //     Rule::exchange_body => {
        //         println!("exchange_body: {exchange_body:?}")
        //     }
        //     _ => None.guaranteed_unwrap(),
        // }
    }
}
