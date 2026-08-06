use std::path::PathBuf;
use rosenpass::config::{RosenpassConfig, rosenpass_peer::RosenpassPeer, verbosity::Verbosity, rosenpass_keypair::RosenpassKeypair};

fn split_str(s: &str) -> Vec<String> {
    s.split(' ').map(|s| s.to_string()).collect()
}
    
#[test]
fn test_cli_parse_multiple_peers() {
    let args = split_str(
        "public-key /my/public-key secret-key /my/secret-key verbose \
            peer public-key /peer-a/public-key endpoint \
            peer.test:9999 outfile /peer-a/rp-out \
            peer public-key /peer-b/public-key outfile /peer-b/rp-out",
    );

    let config = RosenpassConfig::parse_args(args).unwrap();

    assert_eq!(
        config.keypair,
        Some(RosenpassKeypair::new("/my/public-key", "/my/secret-key"))
    );
    assert_eq!(config.verbosity, Verbosity::Verbose);
    assert!(&config.listen.is_empty());
    assert_eq!(
        config.peers,
        vec![
            RosenpassPeer {
                public_key: PathBuf::from("/peer-a/public-key"),
                endpoint: Some("peer.test:9999".into()),
                pre_shared_key: None,
                key_out: Some(PathBuf::from("/peer-a/rp-out")),
                ..Default::default()
            },
            RosenpassPeer {
                public_key: PathBuf::from("/peer-b/public-key"),
                endpoint: None,
                pre_shared_key: None,
                key_out: Some(PathBuf::from("/peer-b/rp-out")),
                ..Default::default()
            }
        ]
    )
}