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
        PqKeypairSource, PublicPqKeySource, RosenpassConfig, SecretPqKeySource, SecretWgKeySource,
        Verbosity, WgDeviceConfig, WgDeviceCreateOptions,
        parse_from_cli::{
            errors::{ParseProblem, ParseProblemError},
            util::parse_rp_peer,
        },
        parse_from_toml::util::GuaranteedUnwrap,
    },
    protocol::ProtocolVersion,
};
use std::{
    cell::OnceCell,
    iter,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    str::FromStr,
};

pub mod errors;
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
    /// `RosenpassConfig::parse_from_entire_cli`
    ///
    /// **NOTE:** pass a command line with `'\0'`-separated arguments. Do not pass `' '`-separated
    /// arguments.
    pub fn parse_from_cli_parameters(
        parameter_line: &str,
        grammar: CliGrammar,
    ) -> ParseResult<RosenpassConfig> {
        declare_issues!(errors, warnings);
        match grammar {
            // `rp` command grammar has some specific quirks:
            // - [x] expect exactly zero or one listen address
            // - [x] if a listen address is set, then the WG device's port will be set to the listen
            //   address' port + 1
            // - [x] the `endpoint` of a peer (optional) does _not_ describe the WG endpoint. It is the
            //   peer's rosenpass endpoint. The peer's WG endpoint will be the same but with
            //   port + 1
            // - [x] our WG device is exactly one (defaults to `rosenpass0` if not set by the user).
            //   It is the same for all peers.
            // - [x] rp always _creates_ a WireGuard device
            // - [x] our WG device is suplied with its secret key (wgsk)
            // - [x] the `ip` parameter can be used to assign the public IP address of our WG device
            //   (optional)
            // - [x] read the peer's WG pubkey from `<peer's pubkey dir>/wgpk` (must exist)
            // - [x] read the PSK shared with a peer from `<peer's pubkey dir>/psk` (only if file
            //   exists)
            // TODO: write unit tests for all of these assumptions
            CliGrammar::Rp => {
                let parsed =
                    match Parser::try_parse::<pairs::rp_exchange_parameters>(parameter_line) {
                        Ok(parsed) => parsed,
                        Err(error) => {
                            let error = error
                                .renamed_rules(rename_rules)
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
                        secret_keys_dir.clone(),
                    )),
                    public_key_source: PublicPqKeySource::new(KeyFromDiskInner::Directory(
                        // sic!, the public keys are always also read from the same directory as the
                        // secret keys by the `rp` command
                        secret_keys_dir.clone(),
                    )),
                };

                // optional parameters
                let verbosity = OnceCell::new();
                let our_listen_address = OnceCell::new();
                let device_name = OnceCell::new();
                let device_ip = OnceCell::new();

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
                    // our listen addresses
                    else if let Some(listen) = option.listen() {
                        let listen = listen.socket_address();

                        our_listen_address
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
                                    Some(listen.span.start()..listen.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneListenAddressInRp(
                                        our_listen_address.get().expect("unreachable").clone(),
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

                // if device name is not set by user, default to `rosenpas0`
                device_name.get_or_init(|| {
                    const DEFAULT_WG_NAME: &str = "rosenpass0";
                    log::warn!(
                        "{message}, defaulting to {DEFAULT_WG_NAME}",
                        message = "no WireGuard device name specified on the command line"
                    );
                    DEFAULT_WG_NAME.into()
                });

                // determine WG device
                // NOTE: this catches errors if the above code defaulting to `rosenpass0` might be
                // removed/disabled in the future
                // NOTE: we are consuming `device_name` and `device_ip` because their data now live
                // in `wireguard_device`. Do not attempt to use the (`device_name`, `device_ip`)
                // product later but refer to the `wireguard_device` let binding instead.
                let wireguard_device = match (device_name.into_inner(), device_ip.into_inner()) {
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
                        name,
                        enabled: true,
                        // rp _always creates_ the WG device, it never uses an existing one
                        created_by: WgDeviceCreateOptions::Create(DeviceWireguardOptions {
                            // TODO: these parameters are not supported by `rp`:
                            // - wg_fwmark

                            // set WG device port to rosenpass' port + 1 (of `listen` parameter
                            // is set at all)
                            wg_listen_port: our_listen_address.get().map(|a| a.port() + 1),
                            wg_fwmark: None,
                            set_ip_addr: addr,
                            // rp _always_ sets the WG secret key as the device is _always_
                            // created by rp.
                            wg_secret_key: Some(SecretWgKeySource::new(
                                KeyFromDiskInner::Directory(secret_keys_dir.clone()),
                            )),
                        }),
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
                        our_listen_addresses: our_listen_address
                            .get()
                            .iter()
                            .cloned()
                            .cloned()
                            .collect::<Vec<SocketAddr>>(),
                        verbosity: verbosity.get().cloned().unwrap_or_default(),
                        our_keypair,
                        // TODO: should `rp` get a command to specify the allowed protocol versions?
                        supported_protocol_versions: ProtocolVersion::all_supported_by_default(),
                        // TODO: implement experimental API feature for `rp` CLI when it is stabilized
                        #[cfg(feature = "experiment_api")]
                        api: ApiConfig::new_empty(),
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
                let our_secret_key = OnceCell::new();
                let our_public_key = OnceCell::new();
                let mut our_listen_addresses = Vec::new();
                let verbosity = OnceCell::new();

                let own_config_options = {
                    let elements = parsed
                        .rosenpass_exchange_body()
                        .rosenpass_own_config()
                        .rosenpass_own_config_element();
                    iter::once(elements.0).chain(elements.1).collect::<Vec<_>>()
                };
                for option in own_config_options {
                    if let Some(seckey) = option.own_secret_key() {
                        our_secret_key
                            .set(PathBuf::from(seckey.path().span.as_str()))
                            .map_err(|e| {
                                ParseError::new(
                                    Some(seckey.span.start()..seckey.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneOurPqSeckey,
                                )
                            })
                            .process_parse_result(&mut errors, &mut warnings);
                    } else if let Some(pubkey) = option.own_public_key() {
                        our_public_key
                            .set(PathBuf::from(pubkey.path().span.as_str()))
                            .map_err(|e| {
                                ParseError::new(
                                    Some(pubkey.span.start()..pubkey.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneOurPqPubkey,
                                )
                            })
                            .process_parse_result(&mut errors, &mut warnings);
                    } else if let Some(listen) = option.listen() {
                        let string = listen.socket_address().span.as_str();
                        let socket = SocketAddr::from_str(string)
                            .map_err(|e| {
                                ParseError::new(
                                    Some(listen.span.start()..listen.span.end()),
                                    parameter_line,
                                    ParseProblemError::InvalidSocketAddr(string.to_string()),
                                )
                            })
                            .process_parse_result(&mut errors, &mut warnings);
                        if let Some(socket) = socket {
                            our_listen_addresses.push(socket);
                        }
                    } else if let Some(v) = option.verbosity() {
                        verbosity
                            .set(parse_verbosity(v))
                            .map_err(|e| {
                                ParseError::new(
                                    Some(v.span.start()..v.span.end()),
                                    parameter_line,
                                    ParseProblemError::MoreThanOneVerbosity(
                                        *verbosity.get().guaranteed_unwrap(),
                                    ),
                                )
                            })
                            .process_parse_result(&mut errors, &mut warnings);
                    } else {
                        unreachable!("unknown option \"{}\"", option.span.as_str());
                    }
                }

                if our_secret_key.get().is_none() {
                    errors.push(ParseProblem::new(
                        None,
                        parameter_line,
                        ParseProblemError::NoOurPqSecretKeySupplied,
                    ));
                }
                if our_public_key.get().is_none() {
                    errors.push(ParseProblem::new(
                        None,
                        parameter_line,
                        ParseProblemError::NoOurPqPublicKeySupplied,
                    ));
                }

                let peers = parsed
                    .rosenpass_exchange_body()
                    .rosenpass_peer()
                    .iter()
                    .enumerate()
                    .filter_map(|(idx, peer)| {
                        parse_rosenpass_peer(peer, idx)
                            .process_parse_result(&mut errors, &mut warnings)
                    })
                    .collect::<Vec<_>>();

                // TODO: devices(?)

                // return on error, then unwrap
                return_on_error!(errors, warnings);
                let our_secret_key = our_secret_key.into_inner().guaranteed_unwrap();
                let our_public_key = our_public_key.into_inner().guaranteed_unwrap();
                let verbosity = verbosity.into_inner().unwrap_or(Verbosity::default());

                // parsed from
                let parsed_from = ConfigSource::CommandLineArguments(ConfigSourceCli {
                    full_command_line: parameter_line.to_string(),
                    full_command_line_human_readable: parameter_line.replace('\0', " "),
                    warnings: warnings.clone(),
                });

                Ok((
                    RosenpassConfig {
                        our_listen_addresses,
                        verbosity,
                        our_keypair: PqKeypairSource {
                            secret_key_source: SecretPqKeySource::new(KeyFromDiskInner::File(
                                our_secret_key,
                            )),
                            public_key_source: PublicPqKeySource::new(KeyFromDiskInner::File(
                                our_public_key,
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
        // common
        Rule::rosenpass_entire_command_line | Rule::rp_entire_command_line => {
            "command line".to_string()
        }
        Rule::rosenpass_exchange_parameters
        | Rule::rp_exchange_parameters
        | Rule::rosenpass_exchange_body
        | Rule::rp_exchange_body => "parameters to the subcommand".into(),
        Rule::verbosity => "[verbose|quiet]".into(),
        Rule::verbosity_verbose => "verbose".into(),
        Rule::verbosity_quiet => "quiet".into(),
        Rule::rosenpass_config_file => "-c | --config-file <FILE>".into(),
        Rule::endpoint => "endpoint <HOST:PORT>".into(),
        Rule::host_port_pair => "<HOST:PORT>".into(),
        Rule::host_name => "name of a network host or an IPv4 or IPv6 address".into(),

        Rule::wireguard_extra_option => "wireguard extra options".into(),
        Rule::wireguard_endpoint => "endpoint <HOST:PORT>".into(),
        Rule::wireguard_persistent_keepalive => "persistent-keepalive <SECONDS>".into(),
        Rule::wireguard_allowed_ips => "allowed-ips <ip1>/<cidr1>[,<ip2>/<cidr2>]...".into(),

        Rule::path => "path to a file or directory".into(),
        Rule::wireguard_device => "wireguard device name".into(),
        Rule::their_wg_pubkey => "their wireguard public key".into(),
        Rule::unsigned_integer => "an unsigned integer".into(),
        Rule::ip_address => "an IPv4 or IPv6 address".into(),
        Rule::cidr => "a CIDR prefix (IPv4 or IPv6)".into(),
        Rule::socket_address => "<IP:PORT>".into(),
        Rule::ip_or_cidr => "IP address or CIDR prefix".into(),
        Rule::network_port => "a network port".into(),
        Rule::ipv4_address => "an IPv4 address".into(),
        Rule::ipv4_octet => "one octet of an IPv4 address".into(),
        Rule::ipv6_address => "IPv6 address".into(),
        Rule::prefix4 => "a number between 0 and 32".into(),
        Rule::prefix6 => "a number between 0 and 128".into(),

        Rule::EOI => "end of command line".into(),
        Rule::separator => "end of argument".into(),

        // RP
        Rule::rp_secret_keys_dir => "path to our secret keys".into(),
        Rule::rp_option => "option to the subcommand".into(),
        Rule::rp_device_option => "device <WG_DEVICE>".into(),
        Rule::rp_ip_option => "ip <IP_ADDRESS>".into(),
        Rule::rp_peer => "peer configuration".into(),
        Rule::rp_peer_pubkey_dir => "path to the peer's public keys directory".into(),

        // Rosenpass
        Rule::rosenpass_own_config => "<OWN_CONFIG>".into(),
        Rule::rosenpass_own_config_element => "item of this instance's configuration".into(),
        Rule::own_public_key => "public-key <FILE>".into(),
        Rule::own_secret_key => "secret-key <FILE>".into(),
        Rule::listen => "listen <IP:PORT>".into(),
        Rule::rosenpass_peer => "peer configuration".into(),
        Rule::peer_public_key => "public-key <FILE>".into(),
        Rule::preshared_key => "preshared-key <FILE>".into(),
        Rule::outfile => "outfile <FILE>".into(),
        Rule::wireguard => "wireguard <DEVICE> <THEIR-PUBLIC-KEY> [OPTIONS]".into(),
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
