//! TODO: doc
//!

use std::{
    iter,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use cidr::IpCidr;

use super::{
    ParseError, ParseIssue, ParseResult, ParseWarning, ProcessParseResult2, declare_issues,
    return_on_error,
};
use crate::config::{
    KeyFromDisk, KeyFromDiskInner, KeyFromDiskOrB64EncodedString,
    KeyFromDiskOrB64EncodedStringInner, NewFromInner, OurWireguardKeypair, OutputToFileConfig,
    PeerConfig, PeerWireguardOptions, PresharedKeySource, PublicPqKeySource, PublicWgKeySource,
    RosenpassPeerOskDomainSeparator, WgKeypairSource, WireguardConfig,
    parse_from_cli::errors::ParseProblemError,
    parse_from_toml::util::{GuaranteedUnwrap, ProcessParseResult, default_peer_name},
};

/// parses a [`PeerConfig`]
///
/// - parameter `index` is the numeric index of the peer, used for naming the peers
pub(crate) fn parse_rosenpass_peer(
    peer: &super::rules::rosenpass_peer<'_>,
    index: usize,
) -> ParseResult<PeerConfig> {
    declare_issues!(errors, warnings);

    let public_key = {
        let raw = peer.peer_public_key().path();
        let parsed = PathBuf::from(raw.span.as_str());
        (raw, parsed)
    };
    let endpoint = {
        let raw = peer.endpoint();
        let parsed = raw.map(|r| r.socket_address().span.as_str().to_string());
        (raw, parsed)
    };
    let preshared_key = {
        let raw = peer.preshared_key();
        let parsed = raw
            .map(|r| PathBuf::from(r.path().span.as_str()))
            .map(PresharedKeySource::ReadFromFile);
        (raw, parsed)
    };
    let outfile = {
        let raw = peer.outfile();
        let parsed =
            raw.map(|r| PathBuf::from(r.path().span.as_str()))
                .map(|r| OutputToFileConfig {
                    enabled: true, // no possibility to disable on the CLI
                    output_file_path: r,
                    osk_domain_separator: Default::default(), // no OSK domain separator on the CLI
                });
        (raw, parsed)
    };
    let wireguard = {
        let raw = peer.wireguard();
        let parsed = raw.and_then(|r| {
            parse_rosenpass_peer_wireguard(r).process_parse_result(&mut errors, &mut warnings)
        });
        (raw, parsed)
    };

    return_on_error!(errors, warnings);

    // return
    Ok((
        PeerConfig {
            // TODO: maybe let the user specify a peer name via CLI in the future?
            name: default_peer_name(index),
            enabled: true, // peers specified in CLI are always enabled
            their_public_key: PublicPqKeySource::new(KeyFromDiskInner::File(public_key.1)),
            endpoint: endpoint.1,
            preshared_key: preshared_key.1,
            // defaults to empty – TODO: eventually introduce this option to the CLI
            osk_domain_separator: Default::default(),
            output_to_file: outfile.1,
            wireguard: wireguard.1,
        },
        warnings,
    ))
}

pub(crate) fn parse_rosenpass_peer_wireguard(
    wireguard: &super::rules::wireguard<'_>,
) -> ParseResult<WireguardConfig> {
    declare_issues!(errors, warnings);

    let device = {
        let raw = wireguard.wireguard_device();
        let parsed = raw.span.as_str().to_string();
        (raw, parsed)
    };
    let their_wg_pubkey = {
        let raw = wireguard.their_wg_pubkey();
        // TODO: is this always a base64-encoded key?
        let parsed = PublicWgKeySource::new(
            KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(raw.span.as_str().to_string()),
        );
        (raw, parsed)
    };
    let wireguard_options = parse_wireguard_options(wireguard.wireguard_extra_option())
        .process_parse_result(&mut errors, &mut warnings);

    return_on_error!(errors, warnings);

    Ok((
        WireguardConfig {
            enabled: true, // no disable option on the CLI
            device_name: device.1,
            our_wireguard_keypair: None, // TODO: introduce support (needed for protocol version 3)
            their_wireguard_public_key: their_wg_pubkey.1,
            wireguard_options: wireguard_options.guaranteed_unwrap(),
            exchange_command: None, // this has never been supported by the CLI and should never be supported
            osk_domain_separator: Default::default(), // defaults to empty // TODO: introduce support
        },
        warnings,
    ))
}

pub(crate) fn parse_rp_peer(
    peer: &super::rules::rp_peer,
    // require index of the peer for generic peer naming
    index: usize,
    // require WG device name because the `RosenpassConfig` allows different peers to use different
    // devices – even though `rp` does currently not allow that
    wireguard_device_name: &str,
    // require our secret keys directory to load our WG keypair
    our_keys_directory: &Path,
) -> ParseResult<PeerConfig> {
    declare_issues!(errors, warnings);

    // peer name
    let name = default_peer_name(index);

    // their rosenpass public key (pqpk)
    let their_public_key = PublicPqKeySource::new(KeyFromDiskInner::Directory(PathBuf::from(
        peer.rp_peer_pubkey_dir().path().span.as_str(),
    )));

    // their wireguard public key (wgpk)
    let their_pubkeys_dir = PathBuf::from(peer.rp_peer_pubkey_dir().path().span.as_str());
    let their_wireguard_public_key = PublicWgKeySource::new(
        KeyFromDiskOrB64EncodedStringInner::Directory(their_pubkeys_dir.clone()),
    );

    // our wgsk/wgpk
    // Technically, we only need our wgpk here (for binding to it in protocol version 3) but if we
    // already have our entire keypair, let us store that in the config – this is more honest and
    // maybe some future feature might want to use that
    let our_wireguard_keypair = Some(OurWireguardKeypair::EntireKeypair(WgKeypairSource {
        secret_key_source: KeyFromDisk::new(KeyFromDiskInner::Directory(
            our_keys_directory.to_path_buf(),
        )),
        public_key_source: KeyFromDiskOrB64EncodedString::new(
            KeyFromDiskOrB64EncodedStringInner::Directory(our_keys_directory.to_path_buf()),
        ),
    }));

    // wireguard options
    // First, parse the WG options naively by assuming that `endpoint` is also part of the WG
    // settings.
    let wireguard_options = parse_wireguard_options(peer.wireguard_extra_option())
        .process_parse_result(&mut errors, &mut warnings);

    // The peer's endpoint is actually the rosenpass endpoint (yes, this is confusing).
    // Extract the peer's endpoint and then set the peer's endpoint by incrementing the port number
    // (this is some convention: WG port i= rosenpass port + 1)
    return_on_error!(errors, warnings);
    let mut wireguard_options = wireguard_options.guaranteed_unwrap();
    // TODO: are we sure that we do not allow a host name?
    let rosenpass_endpoint = SocketAddr::from_str(
        wireguard_options
            .endpoint
            .expect("require endpoint") // TODO: proper error
            .as_str(),
    )
    .expect("invalid socket address"); // TODO: proper error (and support host names?)
    wireguard_options.endpoint =
        Some(SocketAddr::new(rosenpass_endpoint.ip(), rosenpass_endpoint.port() + 1).to_string());

    // set PSK if PSK file exists
    let preshared_key = {
        let psk_source = PresharedKeySource::ReadFromDirectory(their_pubkeys_dir);
        let file = psk_source.get_key_file_path();
        if file.exists() {
            log::info!(
                "using PSK with peer \"{name}\" read from \"{file}\"",
                file = file.display()
            );
            Some(psk_source)
        } else {
            // logging this might be relevant: maybe the file exists but the process lacks access
            // rights
            log::info!("using no PSK with peer \"{name}\"");
            None
        }
    };

    return_on_error!(errors, warnings);

    // TODO
    Ok((
        PeerConfig {
            name,
            enabled: true,
            their_public_key,
            endpoint: Some(rosenpass_endpoint.to_string()),
            preshared_key,
            // TODO: rp might want to support OSK domain separators in the future
            osk_domain_separator: RosenpassPeerOskDomainSeparator::default(),
            output_to_file: None, // rp passes the OSK to WireGuard and no to a file
            wireguard: Some(WireguardConfig {
                enabled: true,
                device_name: wireguard_device_name.to_string(),
                our_wireguard_keypair,
                their_wireguard_public_key,
                wireguard_options,
                exchange_command: None,
                osk_domain_separator: RosenpassPeerOskDomainSeparator::default(),
            }),
        },
        warnings,
    ))
}

pub(crate) fn parse_wireguard_options(
    (opt1, opt2, opt3): (
        Option<&super::rules::wireguard_extra_option>,
        Option<&super::rules::wireguard_extra_option>,
        Option<&super::rules::wireguard_extra_option>,
    ),
) -> ParseResult<PeerWireguardOptions> {
    declare_issues!(errors, warnings);
    let mut options = PeerWireguardOptions {
        endpoint: None,
        persistent_keepalive: None,
        allowed_ips: None,
        wg_extra_arguments: vec![],
    };
    for option in vec![opt1, opt2, opt3].into_iter().flatten() {
        if let Some(endpoint) = option.wireguard_endpoint() {
            if options.endpoint.is_none() {
                options.endpoint = Some(endpoint.socket_address().span.as_str().to_string())
            } else {
                todo!("duplicate item endpoint")
            }
        } else if let Some(persistent_keepalive) = option
            .wireguard_persistent_keepalive()
            .map(|p| p.unsigned_integer())
        {
            if options.persistent_keepalive.is_none() {
                match persistent_keepalive.span.as_str().parse::<usize>() {
                    Ok(persistent_keepalive) => {
                        options.persistent_keepalive = Some(persistent_keepalive)
                    }
                    Err(_) => {
                        ParseError::new(
                            Some(
                                persistent_keepalive.span.start()..persistent_keepalive.span.end(),
                            ),
                            persistent_keepalive.span.get_input(),
                            ParseProblemError::InvalidTimeInSeconds(
                                persistent_keepalive.span.as_str().to_string(),
                            ),
                        )
                        .process_parse_result(&mut errors);
                    }
                }
            }
        } else if let Some(allowed_ips) = option.wireguard_allowed_ips() {
            declare_issues!(allowed_ips_errors, allowed_ips_warnings);
            let (first, following) = allowed_ips.ip_or_cidr();
            let allowed_ips = iter::once(first).chain(following).collect::<Vec<_>>();
            if !allowed_ips.is_empty() {
                let allowed_ips = allowed_ips
                    .into_iter()
                    .map(|ip| {
                        IpCidr::from_str(ip.span.as_str()).map_err(|e| {
                            ParseError::new(
                                Some(ip.span.start()..ip.span.end()),
                                ip.span.get_input(),
                                ParseProblemError::InvalidAddressOrNetwork(
                                    ip.span.as_str().to_string(),
                                ),
                            )
                        })
                    })
                    .collect::<Vec<_>>()
                    .process_parse_result(&mut allowed_ips_errors);
                if !allowed_ips_errors.is_empty() {
                    errors.extend(allowed_ips_errors);
                } else {
                    options.allowed_ips = Some(allowed_ips.guaranteed_unwrap());
                }
                warnings.extend(allowed_ips_warnings);
            }
        } else {
            ParseError::new(
                Some(option.span.start()..option.span.end()),
                option.span.get_input(),
                ParseProblemError::InvalidWireguardExtraOption(option.span.as_str().to_string()),
            )
            .process_parse_result(&mut errors);
        }
    }
    Ok((options, warnings))
}
