//! Simplified Rosenpass connection management for NetworkManager

use crate::{RosenpassConfig, RosenpassNetworkManagerError};
use crate::error::Result;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use tokio::sync::{Mutex, RwLock};
use uuid::Uuid;

/// Connection states for Rosenpass connections
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionState {
    /// Connection is inactive
    Inactive,
    /// Connection is activating
    Activating,
    /// Connection is active and key exchange is running
    Active,
    /// Connection is deactivating
    Deactivating,
    /// Connection failed
    Failed(String),
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::Inactive => write!(f, "inactive"),
            ConnectionState::Activating => write!(f, "activating"),
            ConnectionState::Active => write!(f, "active"),
            ConnectionState::Deactivating => write!(f, "deactivating"),
            ConnectionState::Failed(err) => write!(f, "failed: {}", err),
        }
    }
}

/// A simplified Rosenpass connection that uses the rosenpass binary
pub struct SimpleRosenpassConnection {
    /// Connection UUID
    pub uuid: Uuid,
    
    /// Connection configuration
    pub config: RosenpassConfig,
    
    /// Current connection state
    pub state: Arc<RwLock<ConnectionState>>,
    
    /// The running Rosenpass process (if active)
    process: Arc<Mutex<Option<Child>>>,
    
    /// Configuration file path
    config_file: std::path::PathBuf,
}

impl SimpleRosenpassConnection {
    /// Create a new Rosenpass connection
    pub fn new(config: RosenpassConfig, config_dir: &std::path::Path) -> Result<Self> {
        let config_file = config_dir.join(format!("{}.toml", config.connection_uuid));
        
        Ok(Self {
            uuid: config.connection_uuid,
            config,
            state: Arc::new(RwLock::new(ConnectionState::Inactive)),
            process: Arc::new(Mutex::new(None)),
            config_file,
        })
    }
    
    /// Get the current connection state
    pub async fn get_state(&self) -> ConnectionState {
        self.state.read().await.clone()
    }
    
    /// Activate the connection
    pub async fn activate(&self) -> Result<()> {
        let mut state = self.state.write().await;
        
        match *state {
            ConnectionState::Active => {
                return Err(RosenpassNetworkManagerError::ConnectionActive(
                    self.uuid.to_string()
                ));
            }
            ConnectionState::Activating => {
                // Already activating, just return success
                return Ok(());
            }
            _ => {}
        }
        
        *state = ConnectionState::Activating;
        drop(state); // Release the lock before async operations
        
        // Validate configuration
        self.config.validate()?;
        
        // Save the configuration to a temporary file
        self.config.save_to_file(&self.config_file)?;
        
        // Start the Rosenpass process
        let result = self.start_process().await;
        
        // Update state based on result
        let mut state = self.state.write().await;
        match result {
            Ok(()) => {
                *state = ConnectionState::Active;
                log::info!("Rosenpass connection {} activated", self.uuid);
            }
            Err(err) => {
                let error_msg = err.to_string();
                *state = ConnectionState::Failed(error_msg.clone());
                log::error!("Failed to activate Rosenpass connection {}: {}", self.uuid, error_msg);
                return Err(err);
            }
        }
        
        Ok(())
    }
    
    /// Deactivate the connection
    pub async fn deactivate(&self) -> Result<()> {
        let mut state = self.state.write().await;
        
        match *state {
            ConnectionState::Inactive => {
                return Err(RosenpassNetworkManagerError::ConnectionInactive(
                    self.uuid.to_string()
                ));
            }
            ConnectionState::Deactivating => {
                // Already deactivating, just return success
                return Ok(());
            }
            _ => {}
        }
        
        *state = ConnectionState::Deactivating;
        drop(state); // Release the lock before async operations
        
        // Stop the process
        self.stop_process().await?;
        
        // Update state
        let mut state = self.state.write().await;
        *state = ConnectionState::Inactive;
        
        log::info!("Rosenpass connection {} deactivated", self.uuid);
        Ok(())
    }
    
    /// Start the Rosenpass process
    async fn start_process(&self) -> Result<()> {
        let mut process_guard = self.process.lock().await;
        
        // Stop any existing process
        if let Some(mut child) = process_guard.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        
        // Create the rosenpass configuration in the legacy format
        self.create_legacy_config()?;
        
        // Start the rosenpass process
        let mut command = Command::new("rosenpass");
        command
            .arg("exchange-config")
            .arg(&self.config_file)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        
        if self.config.verbose {
            command.arg("--verbose");
        }
        
        let child = command
            .spawn()
            .map_err(|e| RosenpassNetworkManagerError::Io(e))?;
        
        *process_guard = Some(child);
        
        log::info!("Started Rosenpass process for connection {}", self.uuid);
        Ok(())
    }
    
    /// Stop the Rosenpass process
    async fn stop_process(&self) -> Result<()> {
        let mut process_guard = self.process.lock().await;
        
        if let Some(mut child) = process_guard.take() {
            // Try to terminate gracefully first
            if let Err(e) = child.kill() {
                log::warn!("Failed to kill Rosenpass process for connection {}: {}", self.uuid, e);
            }
            
            // Wait for the process to exit
            match child.wait() {
                Ok(status) => {
                    log::info!("Rosenpass process for connection {} exited with status: {}", 
                              self.uuid, status);
                }
                Err(e) => {
                    log::error!("Failed to wait for Rosenpass process for connection {}: {}", 
                               self.uuid, e);
                }
            }
        }
        
        Ok(())
    }
    
    /// Create a legacy Rosenpass configuration
    fn create_legacy_config(&self) -> Result<()> {
        // Convert our config to the standard Rosenpass config format
        let rp_config = self.config.to_rosenpass_config();
        
        // Save it to the config file
        let config_content = format!(
            "# Rosenpass configuration for NetworkManager connection {}\n{}",
            self.uuid,
            toml::to_string_pretty(&rp_config)
                .map_err(|e| RosenpassNetworkManagerError::Io(
                    std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string())
                ))?
        );
        
        std::fs::write(&self.config_file, config_content)?;
        
        Ok(())
    }
}