//! TODO: doc (add proper `README.md` here)
//!
//! TODO: parse rp format
//! TODO: parse config subcommand (separate module)

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
    cli::CliGrammar,
    config::{
        ConfigSource, ConfigSourceCli, DeviceWireguardOptions, KeyFromDiskInner, NewFromInner,
        PeerConfig, PqKeypairSource, PublicPqKeySource, RosenpassConfig,
        RosenpassPeerOskDomainSeparator, SecretPqKeySource, Verbosity, WgDeviceConfig,
        WgDeviceCreateOptions,
        parse_from_cli::{
            errors::ParseProblemError,
            util::{parse_rosenpass_peer_wireguard, parse_rp_peer, parse_wireguard_options},
        },
        parse_from_toml::util::{GuaranteedUnwrap, ProcessParseResult, default_peer_name},
    },
    internal::util::result::OkExt,
    protocol::ProtocolVersion,
};
use std::{
    cell::OnceCell,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

pub mod errors;
use anyhow::bail;
pub use errors::{ParseError, ParseIssue, ParseResult, ParseWarning};
use errors::{ProcessParseResult2, declare_issues, return_on_error};

pub(crate) mod util;
use util::parse_rosenpass_peer;

// use pest::Parser;
// use pest_derive::Parser;
// #[derive(Parser)]
// #[grammar = "config/parse_from_cli/rosenpass.pest"]
// struct RosenpassParser;

use pest_typed::TypedParser;
use pest_typed_derive::TypedParser;

#[derive(TypedParser)]
#[grammar = "config/parse_from_cli/exchange.pest"]
#[emit_rule_reference]
struct Parser;

impl RosenpassConfig {
    /// convenience wrapper around [`RosenpassConfig::parse_from_cli_parameters`] which removes the
    /// first two arguments, typically `rosenpass exchange`
    ///
    /// This is typically only used by unit tests. Usually, you should call
    /// [`RosenpassConfig::parse_from_cli_parameters`] with the first two parameters omitted. See
    /// [`crate::cli::CliCommand::parse`] as an entrypoint which will call
    /// [`RosenpassConfig::parse_from_cli_parameters`].
    #[cfg(test)]
    pub fn parse_from_entire_cli(
        full_line: &str,
        grammar: CliGrammar,
    ) -> ParseResult<RosenpassConfig> {
        Self::parse_from_cli_parameters(
            full_line
                .split('\0')
                .skip(2)
                .collect::<Vec<&str>>()
                .join("\0")
                .as_str(),
            grammar,
        )
    }

    /// parses the command line parameters after a `rosenpass exchange` or `rp exchange` into a
    /// [`RosenpassConfig`]
    ///
    /// **NOTE:** do not pass the entire command line but only the part after `{tool_name} exchange`.
    /// For a convenience wrapper which uses the entire command line, see
    /// [`RosenpassConfig::parse_from_entire_cli`]
    ///
    /// **NOTE:** pass a command line with `'\0'`-separated arguments. Do not pass `' '`-separated
    /// arguments.
    pub fn parse_from_cli_parameters(
        parameter_line: &str,
        grammar: CliGrammar,
    ) -> ParseResult<RosenpassConfig> {
        declare_issues!(errors, warnings);
        match grammar {
            CliGrammar::Rp => {
                let parsed =
                    match Parser::try_parse::<pairs::rp_exchange_parameters>(parameter_line) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            let error = error
                                .renamed_rules(f)
                                .with_path("command line")
                                .to_string()
                                .replace('\0', " ");
                            return Err(vec![ParseIssue::Error(ParseError::new(
                                // TODO: use correct span
                                None,
                                parameter_line,
                                errors::ParseProblemError::InvalidCommandLineSyntax(error),
                            ))]);
                        }
                    };
                let parsed = parsed.rp_exchange_body();

                // our keypair
                let secret_keys_dir =
                    PathBuf::from(parsed.rp_secret_keys_dir().path().span.as_str());
                let our_keypair = PqKeypairSource {
                    secret_key_source: SecretPqKeySource::new(KeyFromDiskInner::Directory(
                        secret_keys_dir,
                    )),
                    public_key_source: PublicPqKeySource::new(KeyFromDiskInner::Directory(
                        // sic!, the public keys are always also read from the same directory as the
                        // secret keys by the `rp` command
                        secret_keys_dir,
                    )),
                };

                let mut verbosity = OnceCell::new();
                let mut our_listen_addresses = OnceCell::new();
                // TODO: implement experimental API feature for `rp` CLI when it is stabilized
                #[cfg(feature = "experiment_api")]
                let mut api = ApiConfig::new_empty();
                let mut peers = Vec::new();

                let mut device_name = OnceCell::new();
                let mut device_ip = OnceCell::new();

                for option in parsed.rp_option() {
                    // device name
                    if let Some(device) = option.rp_device_option() {
                        let device = device.wireguard_device();
                        device_name
                            .set(device.span.as_str().to_string())
                            .map_err(|e| {
                                vec![ParseIssue::Error(ParseError::new(
                                    Some(device.span.start()..device.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneDeviceNameInRp(
                                        device_name.get().expect("unreachable").clone(),
                                    ),
                                ))]
                            })?;
                    }
                    // ip address for the device
                    else if let Some(ip) = option.rp_ip_option() {
                        let ip = ip.ip_address();
                        device_ip
                            .set(IpAddr::from_str(ip.span.as_str()).map_err(|_err| {
                                vec![ParseIssue::Error(ParseError::new(
                                    Some(ip.span.start()..ip.span.end()),
                                    parameter_line,
                                    ParseProblemError::InvalidIpAddress(
                                        ip.span.as_str().to_string(),
                                    ),
                                ))]
                            })?)
                            .map_err(|e| {
                                vec![ParseIssue::Error(ParseError::new(
                                    Some(ip.span.start()..ip.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneDeviceAddressInRp(
                                        device_ip.get().expect("unreachable").clone(),
                                    ),
                                ))]
                            })?;
                    }
                    // out listen addresses
                    else if let Some(listen) = option.listen() {
                        let listen = listen.socket_address();

                        our_listen_addresses
                            .set(SocketAddr::from_str(listen.span.as_str()).map_err(|_err| {
                                vec![ParseIssue::Error(ParseError::new(
                                    Some(listen.span.start()..listen.span.end()),
                                    parameter_line,
                                    ParseProblemError::InvalidSocketAddr(
                                        listen.span.as_str().to_string(),
                                    ),
                                ))]
                            })?)
                            .map_err(|e| {
                                vec![ParseIssue::Error(ParseError::new(
                                    Some(ip.span.start()..ip.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneListenAddressInRp(
                                        our_listen_addresses.get().expect("unreachable").clone(),
                                    ),
                                ))]
                            })?;
                    }
                    // verbosity
                    else if let Some(v) = option.verbosity() {
                        verbosity.set(parse_verbosity(v)).map_err(|_err| {
                            vec![ParseIssue::Error(ParseError::new(
                                Some(v.span.start()..v.span.end()),
                                parameter_line,
                                ParseProblemError::MultipleVerbosity(
                                    verbosity.get().expect("unreachable").clone(),
                                ),
                            ))]
                        })?;
                    } else {
                        // TODO: this is unreachable but maybe we still want to return a recoverable
                        // error?
                        panic!("unknown rp paramater: {}", option.span.as_str());
                    }
                }

                let wireguard_device = match (device_name.get(), device_ip.get()) {
                    // no wg device specified but `rp` requires this
                    (None, None) => {
                        return Err(vec![ParseIssue::Error(ParseError::new(
                            None,
                            parameter_line,
                            ParseProblemError::NoWireguardDeviceInRp,
                        ))]);
                    }
                    // wg device specified
                    (Some(name), addr) => WgDeviceConfig {
                        name: name.clone(),
                        enabled: true,
                        created_by: WgDeviceCreateOptions::Create(
                            // TODO: these parameters are not supported by `rp`
                            DeviceWireguardOptions {
                                wg_listen_port: None,
                                wg_fwmark: None,
                                set_ip_addr: addr.cloned(),
                                set_listen_addr: todo!(),
                                set_private_key: todo!(),
                            },
                        ),
                    },
                    (None, Some(addr)) => {
                        return Err(vec![ParseIssue::Error(ParseError::new(
                            // TODO: add span?
                            None,
                            parameter_line,
                            ParseProblemError::WgDeviceAddressWithoutNameInRp(addr.clone()),
                        ))]);
                    }
                };

                let peers = parsed
                    .rp_peer()
                    .iter()
                    .enumerate()
                    .filter_map(|(index, peer)| {
                        // TODO: restrict `wireguard_devices`: it should not be a Vec<_> but a OnceC
                        parse_rp_peer(peer, index, &wireguard_device.name, &secret_keys_dir)
                            .process_parse_result(&mut errors, &mut warnings)
                    })
                    .collect::<Vec<_>>();

                // parsed from
                // TODO: this is not DRY, the same `parse_from` is written for `CliGrammar:Rosenpass`
                let parsed_from = ConfigSource::CommandLineArguments(ConfigSourceCli {
                    full_command_line: parameter_line.to_string(),
                    full_command_line_human_readable: parameter_line.replace('\0', " "),
                    warnings: warnings.clone(),
                });

                Ok((
                    RosenpassConfig {
                        our_listen_addresses: our_listen_addresses
                            .get()
                            .iter()
                            .cloned()
                            .cloned()
                            .collect::<Vec<SocketAddr>>(),
                        verbosity: verbosity.get().cloned().unwrap_or_default(),
                        our_keypair,
                        // TODO: should `rp` get a command to specify the allowed protocol versions?
                        supported_protocol_versions: ProtocolVersion::all_supported_by_default(),
                        #[cfg(feature = "experiment_api")]
                        api,
                        wireguard_devices: vec![wireguard_device],
                        peers,
                        parsed_from,
                    },
                    warnings,
                ))
            }
            CliGrammar::Rosenpass => {
                let parsed =
                    match Parser::try_parse::<pairs::rosenpass_exchange_parameters>(parameter_line)
                    {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            let error = (*error)
                                .renamed_rules(rename_rules)
                                .with_path("command line");
                            let error = error.to_string().replace('\0', " ");
                            return Err(vec![ParseIssue::Error(ParseError::new(
                                // TODO: use correct span
                                None,
                                parameter_line,
                                errors::ParseProblemError::InvalidCommandLineSyntax(error),
                            ))]);
                        }
                    };

                // our own config
                let own_config = parsed.rosenpass_exchange_body().own_config();
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
                            let span = l.socket_address().span;
                            let s = span.as_str();
                            SocketAddr::from_str(s).map_err(|e| {
                                ParseError::new(
                                    Some(span.start()..span.end()),
                                    parameter_line,
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
                        .map(parse_verbosity)
                        .unwrap_or_default()
                };

                let peers = parsed
                    .rosenpass_exchange_body()
                    .peer()
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, peer)| {
                        parse_rosenpass_peer(peer, idx)
                            .process_parse_result(&mut errors, &mut warnings)
                    })
                    .collect::<Vec<_>>();

                // TODO: devices(?)

                return_on_error!(errors, warnings);

                // parsed from
                let parsed_from = ConfigSource::CommandLineArguments(ConfigSourceCli {
                    full_command_line: parameter_line.to_string(),
                    full_command_line_human_readable: parameter_line.replace('\0', " "),
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
            }
        }
    }
}

// TODO: put this in `util` submodule
fn rename_rules(rule: &Rule) -> String {
    match *rule {
        Rule::ip_address => "an IP address".into(),
        Rule::cidr => "a CIDR prefix".into(),
        Rule::peer => "a peer configuration".into(),
        Rule::own_config => "own configuration".into(),
        Rule::EOI => "end of command line".into(),
        Rule::separator => "end of argument".into(),
    }
}

fn parse_verbosity(raw: &rules::verbosity) -> Verbosity {
    if raw.verbosity_verbose().is_some() {
        Verbosity::Verbose
    } else if raw.verbosity_quiet().is_some() {
        Verbosity::Quiet
    } else {
        panic!("unexpected verbosity");
    }
}
