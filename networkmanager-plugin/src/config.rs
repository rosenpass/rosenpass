//! Configuration handling for the NetworkManager plugin

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use uuid::Uuid;
use crate::error::Result;

#[cfg(test)]
#[path = "config_test.rs"]
mod config_test;

/// Configuration for a Rosenpass connection in NetworkManager
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosenpassConfig {
    /// Connection UUID from NetworkManager
    pub connection_uuid: Uuid,
    
    /// Path to our public key file
    pub public_key: PathBuf,
    
    /// Path to our secret key file  
    pub secret_key: PathBuf,
    
    /// Port to listen on for incoming connections
    pub listen_port: u16,
    
    /// Optional listen addresses (defaults to all interfaces)
    #[serde(default)]
    pub listen_addresses: Vec<String>,
    
    /// Peer configurations
    pub peers: Vec<PeerConfig>,
    
    /// WireGuard interface name
    pub wireguard_interface: String,
    
    /// Optional pre-shared key file path
    pub preshared_key: Option<PathBuf>,
    
    /// Key output file path for WireGuard integration
    pub key_output: Option<PathBuf>,
    
    /// Enable verbose logging
    #[serde(default)]
    pub verbose: bool,
}

/// Configuration for a Rosenpass peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerConfig {
    /// Peer's public key file path
    pub public_key: PathBuf,
    
    /// Peer's endpoint (IP:port)
    pub endpoint: Option<String>,
    
    /// Optional pre-shared key for this peer
    pub preshared_key: Option<PathBuf>,
    
    /// WireGuard peer public key
    pub wireguard_peer: String,
}

impl RosenpassConfig {
    /// Load configuration from a TOML file
    pub fn load_from_file(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: RosenpassConfig = toml::from_str(&content)?;
        Ok(config)
    }
    
    /// Save configuration to a TOML file
    pub fn save_to_file(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)
            .map_err(|e| crate::RosenpassNetworkManagerError::Io(
                std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
            ))?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    /// Validate the configuration
    pub fn validate(&self) -> Result<()> {
        // Check that key files exist
        if !self.public_key.exists() {
            return Err(crate::RosenpassNetworkManagerError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Public key file not found: {:?}", self.public_key)
                )
            ));
        }
        
        if !self.secret_key.exists() {
            return Err(crate::RosenpassNetworkManagerError::Io(
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("Secret key file not found: {:?}", self.secret_key)
                )
            ));
        }
        
        // Validate peer configurations
        for (i, peer) in self.peers.iter().enumerate() {
            if !peer.public_key.exists() {
                return Err(crate::RosenpassNetworkManagerError::Io(
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("Peer {} public key file not found: {:?}", i, peer.public_key)
                    )
                ));
            }
            
            if let Some(ref psk_path) = peer.preshared_key {
                if !psk_path.exists() {
                    return Err(crate::RosenpassNetworkManagerError::Io(
                        std::io::Error::new(
                            std::io::ErrorKind::NotFound,
                            format!("Peer {} PSK file not found: {:?}", i, psk_path)
                        )
                    ));
                }
            }
        }
        
        Ok(())
    }
    
    /// Convert to Rosenpass configuration format
    pub fn to_rosenpass_config(&self) -> rosenpass::config::Rosenpass {
        use rosenpass::config::*;
        
        // Set up keypair
        let keypair = Some(Keypair {
            public_key: self.public_key.clone(),
            secret_key: self.secret_key.clone(),
        });
        
        // Set up listen addresses
        let listen = if self.listen_addresses.is_empty() {
            vec![format!("0.0.0.0:{}", self.listen_port)
                .parse()
                .expect("Invalid listen address")]
        } else {
            self.listen_addresses
                .iter()
                .map(|addr| {
                    if addr.contains(':') {
                        addr.parse().expect("Invalid listen address")
                    } else {
                        format!("{}:{}", addr, self.listen_port)
                            .parse()
                            .expect("Invalid listen address")
                    }
                })
                .collect()
        };
        
        // Set up peers
        let peers = self.peers
            .iter()
            .map(|peer| RosenpassPeer {
                public_key: peer.public_key.clone(),
                endpoint: peer.endpoint.clone(),
                pre_shared_key: peer.preshared_key.clone(),
                key_out: self.key_output.clone(),
                wg: Some(WireGuard {
                    device: self.wireguard_interface.clone(),
                    peer: peer.wireguard_peer.clone(),
                    extra_params: Vec::new(),
                }),
                protocol_version: ProtocolVersion::V02,
                osk_domain_separator: RosenpassPeerOskDomainSeparator::default(),
            })
            .collect();
        
        let verbosity = if self.verbose { 
            Verbosity::Verbose 
        } else { 
            Verbosity::Quiet 
        };
        
        Rosenpass {
            keypair,
            #[cfg(feature = "experiment_api")]
            api: rosenpass::config::empty_api_config(),
            listen,
            verbosity,
            peers,
            config_file_path: std::path::PathBuf::new(), // Will be set when saved
        }
    }
}