#[cfg(test)]
mod tests {
    use crate::config::{RosenpassConfig, PeerConfig};
    use crate::error::Result;
    use tempfile::TempDir;
    use uuid::Uuid;

    #[test]
    fn test_config_creation() {
        let config = RosenpassConfig {
            connection_uuid: Uuid::new_v4(),
            public_key: "/tmp/public.key".into(),
            secret_key: "/tmp/secret.key".into(),
            listen_port: 9999,
            listen_addresses: vec!["127.0.0.1".to_string()],
            peers: vec![],
            wireguard_interface: "wg0".to_string(),
            preshared_key: None,
            key_output: None,
            verbose: false,
        };

        assert_eq!(config.listen_port, 9999);
        assert_eq!(config.wireguard_interface, "wg0");
    }

    #[test]
    fn test_config_to_rosenpass_conversion() {
        let config = RosenpassConfig {
            connection_uuid: Uuid::new_v4(),
            public_key: "/tmp/public.key".into(),
            secret_key: "/tmp/secret.key".into(),
            listen_port: 9999,
            listen_addresses: vec![],
            peers: vec![PeerConfig {
                public_key: "/tmp/peer.pub".into(),
                endpoint: Some("1.2.3.4:9999".to_string()),
                preshared_key: None,
                wireguard_peer: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=".to_string(),
            }],
            wireguard_interface: "wg0".to_string(),
            preshared_key: None,
            key_output: None,
            verbose: true,
        };

        let rp_config = config.to_rosenpass_config();
        
        assert!(rp_config.keypair.is_some());
        assert_eq!(rp_config.peers.len(), 1);
        assert_eq!(rp_config.listen.len(), 1);
        assert_eq!(rp_config.verbosity, rosenpass::config::Verbosity::Verbose);
    }

    #[test]
    fn test_config_save_and_load() -> Result<()> {
        let temp_dir = TempDir::new()?;
        let config_path = temp_dir.path().join("test.toml");

        let config = RosenpassConfig {
            connection_uuid: Uuid::parse_str("550e8400-e29b-41d4-a716-446655440000").unwrap(),
            public_key: "/tmp/public.key".into(),
            secret_key: "/tmp/secret.key".into(),
            listen_port: 9999,
            listen_addresses: vec!["192.168.1.1".to_string()],
            peers: vec![],
            wireguard_interface: "wg0".to_string(),
            preshared_key: None,
            key_output: Some("/tmp/key.out".into()),
            verbose: false,
        };

        // Save config
        config.save_to_file(&config_path)?;

        // Load config
        let loaded_config = RosenpassConfig::load_from_file(&config_path)?;

        assert_eq!(loaded_config.connection_uuid, config.connection_uuid);
        assert_eq!(loaded_config.listen_port, config.listen_port);
        assert_eq!(loaded_config.listen_addresses, config.listen_addresses);
        assert_eq!(loaded_config.key_output, config.key_output);

        Ok(())
    }
}