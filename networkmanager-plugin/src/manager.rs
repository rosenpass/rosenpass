//! Connection manager for Rosenpass NetworkManager plugin

use crate::{
    SimpleRosenpassConnection, 
    RosenpassConfig, 
    RosenpassNetworkManagerError,
    simple_connection::ConnectionState,
    dbus_service::DBusSignalEmitter,
    error::Result,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::RwLock;
use uuid::Uuid;

/// Manages Rosenpass connections for NetworkManager
pub struct RosenpassConnectionManager {
    /// Active connections keyed by UUID
    connections: Arc<RwLock<HashMap<Uuid, Arc<SimpleRosenpassConnection>>>>,
    
    /// Configuration directory path
    config_dir: PathBuf,
    
    /// D-Bus signal emitter (optional)
    signal_emitter: Option<Arc<DBusSignalEmitter>>,
}

impl RosenpassConnectionManager {
    /// Create a new connection manager
    pub fn new(config_dir: PathBuf) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            config_dir,
            signal_emitter: None,
        }
    }
    
    /// Set the D-Bus signal emitter
    pub fn set_signal_emitter(&mut self, emitter: Arc<DBusSignalEmitter>) {
        self.signal_emitter = Some(emitter);
    }
    
    /// Load all connection configurations from the config directory
    pub async fn load_configurations(&self) -> Result<()> {
        let mut connections = self.connections.write().await;
        
        // Clear existing connections
        connections.clear();
        
        // Read all .toml files from the config directory
        let entries = std::fs::read_dir(&self.config_dir)?;
        
        for entry in entries {
            let entry = entry?;
            let path = entry.path();
            
            if path.extension().and_then(|s| s.to_str()) == Some("toml") {
                match RosenpassConfig::load_from_file(&path) {
                    Ok(config) => {
                        match SimpleRosenpassConnection::new(config, &self.config_dir) {
                            Ok(connection) => {
                                let connection = Arc::new(connection);
                                connections.insert(connection.uuid, connection.clone());
                                
                                log::info!("Loaded configuration for connection: {}", connection.uuid);
                                
                                // Set up state change monitoring
                                if let Some(ref emitter) = self.signal_emitter {
                                    self.start_state_monitoring(connection, emitter.clone()).await;
                                }
                            }
                            Err(err) => {
                                log::error!("Failed to create connection from {:?}: {}", path, err);
                            }
                        }
                    }
                    Err(err) => {
                        log::error!("Failed to load configuration from {:?}: {}", path, err);
                    }
                }
            }
        }
        
        log::info!("Loaded {} connection configurations", connections.len());
        Ok(())
    }
    
    /// Activate a connection by UUID
    pub async fn activate_connection(&self, uuid_str: &str) -> Result<()> {
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| RosenpassNetworkManagerError::InvalidUuid(uuid_str.to_string()))?;
        
        let connections = self.connections.read().await;
        let connection = connections
            .get(&uuid)
            .ok_or_else(|| RosenpassNetworkManagerError::ConnectionNotFound(uuid_str.to_string()))?
            .clone();
        
        drop(connections); // Release the read lock
        
        connection.activate().await
    }
    
    /// Deactivate a connection by UUID
    pub async fn deactivate_connection(&self, uuid_str: &str) -> Result<()> {
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| RosenpassNetworkManagerError::InvalidUuid(uuid_str.to_string()))?;
        
        let connections = self.connections.read().await;
        let connection = connections
            .get(&uuid)
            .ok_or_else(|| RosenpassNetworkManagerError::ConnectionNotFound(uuid_str.to_string()))?
            .clone();
        
        drop(connections); // Release the read lock
        
        connection.deactivate().await
    }
    
    /// Get the status of a connection
    pub async fn get_connection_status(&self, uuid_str: &str) -> Result<ConnectionState> {
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| RosenpassNetworkManagerError::InvalidUuid(uuid_str.to_string()))?;
        
        let connections = self.connections.read().await;
        let connection = connections
            .get(&uuid)
            .ok_or_else(|| RosenpassNetworkManagerError::ConnectionNotFound(uuid_str.to_string()))?;
        
        Ok(connection.get_state().await)
    }
    
    /// List all connection UUIDs
    pub async fn list_connections(&self) -> Vec<Uuid> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }
    
    /// Add a new connection configuration
    pub async fn add_connection(
        &self,
        uuid_str: &str,
        config_path: &PathBuf,
    ) -> Result<()> {
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| RosenpassNetworkManagerError::InvalidUuid(uuid_str.to_string()))?;
        
        // Load the configuration
        let mut config = RosenpassConfig::load_from_file(config_path)?;
        config.connection_uuid = uuid;
        
        // Validate the configuration
        config.validate()?;
        
        // Create the connection
        let connection = Arc::new(SimpleRosenpassConnection::new(config.clone(), &self.config_dir)?);
        
        // Store it in our map
        let mut connections = self.connections.write().await;
        connections.insert(uuid, connection.clone());
        drop(connections);
        
        // Save the configuration to our config directory
        let config_file_path = self.config_dir.join(format!("{}.toml", uuid));
        config.save_to_file(&config_file_path)?;
        
        // Set up state change monitoring
        if let Some(ref emitter) = self.signal_emitter {
            self.start_state_monitoring(connection, emitter.clone()).await;
        }
        
        log::info!("Added connection configuration: {}", uuid);
        Ok(())
    }
    
    /// Remove a connection configuration
    pub async fn remove_connection(&self, uuid_str: &str) -> Result<()> {
        let uuid = Uuid::parse_str(uuid_str)
            .map_err(|_| RosenpassNetworkManagerError::InvalidUuid(uuid_str.to_string()))?;
        
        // Get the connection and deactivate it if active
        let connection = {
            let connections = self.connections.read().await;
            connections.get(&uuid).cloned()
        };
        
        if let Some(connection) = connection {
            // Deactivate if active
            let state = connection.get_state().await;
            if matches!(state, ConnectionState::Active | ConnectionState::Activating) {
                connection.deactivate().await?;
            }
        }
        
        // Remove from our map
        let mut connections = self.connections.write().await;
        connections.remove(&uuid);
        drop(connections);
        
        // Remove the configuration file
        let config_file_path = self.config_dir.join(format!("{}.toml", uuid));
        if config_file_path.exists() {
            std::fs::remove_file(&config_file_path)?;
        }
        
        log::info!("Removed connection configuration: {}", uuid);
        Ok(())
    }
    
    /// Reload all configuration files
    pub async fn reload_configuration(&self) -> Result<()> {
        log::info!("Reloading configuration files");
        
        // Deactivate all active connections
        let connections = self.connections.read().await;
        for connection in connections.values() {
            let state = connection.get_state().await;
            if matches!(state, ConnectionState::Active | ConnectionState::Activating) {
                if let Err(err) = connection.deactivate().await {
                    log::error!("Failed to deactivate connection {} during reload: {}", 
                              connection.uuid, err);
                }
            }
        }
        drop(connections);
        
        // Reload configurations
        self.load_configurations().await?;
        
        log::info!("Configuration reload completed");
        Ok(())
    }
    
    /// Start monitoring state changes for a connection
    async fn start_state_monitoring(
        &self,
        connection: Arc<SimpleRosenpassConnection>,
        emitter: Arc<DBusSignalEmitter>,
    ) {
        let uuid = connection.uuid;
        let state_arc = connection.state.clone();
        
        tokio::spawn(async move {
            let mut last_state = ConnectionState::Inactive;
            
            loop {
                let current_state = {
                    let state = state_arc.read().await;
                    state.clone()
                };
                
                if current_state != last_state {
                    let uuid_str = uuid.to_string();
                    let state_str = current_state.to_string();
                    
                    if let Err(err) = emitter.emit_connection_state_changed(
                        &uuid_str,
                        &state_str,
                    ).await {
                        log::error!("Failed to emit state change signal for {}: {}", uuid, err);
                    }
                    
                    // Emit error signal if connection failed
                    if let ConnectionState::Failed(ref error) = current_state {
                        if let Err(err) = emitter.emit_error_occurred(
                            &uuid_str,
                            error,
                        ).await {
                            log::error!("Failed to emit error signal for {}: {}", uuid, err);
                        }
                    }
                    
                    last_state = current_state;
                }
                
                // Check state every second
                tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            }
        });
    }
}