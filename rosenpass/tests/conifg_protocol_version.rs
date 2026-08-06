use rosenpass::config::{ProtocolVersion, RosenpassConfig, RosenpassPeer};
mod common;
use common::assert_toml_round;

#[test]
fn test_protocol_version() {
    let mut rosenpass = RosenpassConfig::empty();
    let mut peer_v_02 = RosenpassPeer::default();
    peer_v_02.protocol_version = ProtocolVersion::V02;
    rosenpass.peers.push(peer_v_02);
    let mut peer_v_03 = RosenpassPeer::default();
    peer_v_03.protocol_version = ProtocolVersion::V03;
    rosenpass.peers.push(peer_v_03);
    #[cfg(feature = "experiment_api")]
    {
        rosenpass.api.listen_fd = vec![];
        rosenpass.api.listen_path = vec![];
        rosenpass.api.stream_fd = vec![];
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
    assert_toml_round(rosenpass, expected_toml).unwrap()
}
