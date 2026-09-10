use rosenpass::{cfg, cfg::util::assert_toml_round};

#[test]
fn test_protocol_version() {
    let mut config = cfg::AppServer::empty();
    let mut peer_v_02 = cfg::Peer::default();
    peer_v_02.protocol_version = cfg::ProtocolVersion::V02;
    config.peers.push(peer_v_02);
    let mut peer_v_03 = cfg::Peer::default();
    peer_v_03.protocol_version = cfg::ProtocolVersion::V03;
    config.peers.push(peer_v_03);
    #[cfg(feature = "experiment_api")]
    {
        config.api.listen_fd = vec![];
        config.api.listen_path = vec![];
        config.api.stream_fd = vec![];
    }
    #[cfg(feature = "experiment_api")]
    let expected_toml = r#"listen = []
        verbosity = "Quiet"
        
        [api]
        listen_fd = []
        listen_path = []
        stream_fd = []

        [[peers]]
        protocol_version = "V02"
        public_key = ""

        [[peers]]
        protocol_version = "V03"
        public_key = ""
        "#;
    #[cfg(not(feature = "experiment_api"))]
    let expected_toml = r#"listen = []
        verbosity = "Quiet"

        [[peers]]
        protocol_version = "V02"
        public_key = ""

        [[peers]]
        protocol_version = "V03"
        public_key = ""
        "#;
    assert_toml_round(config, expected_toml).unwrap()
}
