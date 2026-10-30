use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use rosenpass::config::{
    OutputToFileConfig, PublicKeySource, RosenpassConfig, RosenpassPeerOskDomainSeparator,
    Verbosity, tests::test_cli::replace_spaces,
};

#[cfg(test)]
#[test]
fn parse_simple() {
    let argv = "public-key /my/public-key secret-key /my/secret-key verbose \
                listen 0.0.0.0:9999 peer public-key /peer/public-key endpoint \
                peer.test:9999 outfile /peer/rp-out";
    let argv = replace_spaces(argv); // replace continues whitespace with '\0'

    let (config, _warnings) = RosenpassConfig::parse_from_cli(argv.as_str()).unwrap();

    // our config
    assert_eq!(
        config.our_keypair.secret_key_source.get_key_path(),
        PathBuf::from("/my/public-key")
    );
    assert_eq!(
        config.our_keypair.public_key_source.get_key_path(),
        PathBuf::from("/my/secret-key")
    );
    assert_eq!(config.verbosity, Verbosity::Verbose);
    assert_eq!(
        &config.our_listen_addresses,
        &vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9999)]
    );

    // peer
    assert_eq!(config.peers.len(), 1);
    let peer = config.peers.get(0).unwrap();
    assert_eq!(peer.enabled, true);
    assert_eq!(peer.endpoint, Some("peer.test:9999".into()));
    assert_eq!(
        peer.their_public_key.get_key_path(),
        PathBuf::from("/peer/public-key")
    );
    assert_eq!(peer.preshared_key, None);
    assert_eq!(
        peer.output_to_file,
        Some(OutputToFileConfig {
            enabled: true,
            output_file_path: PathBuf::from("/peer/rp-out"),
            osk_domain_separator: RosenpassPeerOskDomainSeparator::default()
        })
    );
}
