use rosenpass::config;
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

#[test]
fn parse_simple() {
    let argv = "public-key /my/public-key secret-key /my/secret-key verbose \
                listen 0.0.0.0:9999 peer public-key /peer/public-key endpoint \
                peer.test:9999 outfile /peer/rp-out";
    let argv = argv.split(' ').map(|s| s.to_string()).collect();

    let config = config::RosenpassCfg::parse_args(argv).unwrap();

    assert_eq!(
        config.keypair,
        Some(config::RosenpassKeypair::new(
            "/my/public-key",
            "/my/secret-key"
        ))
    );
    assert_eq!(config.verbosity, config::Verbosity::Verbose);
    assert_eq!(
        &config.listen,
        &vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)), 9999)]
    );
    assert_eq!(
        config.peers,
        vec![config::RosenpassPeer {
            public_key: PathBuf::from("/peer/public-key"),
            endpoint: Some("peer.test:9999".into()),
            pre_shared_key: None,
            key_out: Some(PathBuf::from("/peer/rp-out")),
            ..Default::default()
        }]
    );
}
