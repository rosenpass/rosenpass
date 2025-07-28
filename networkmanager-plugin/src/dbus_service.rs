//! D-Bus service implementation for NetworkManager integration

use crate::{
    RosenpassConnectionManager, 
    RosenpassNetworkManagerError
};
use std::sync::Arc;
use zbus::{interface, SignalContext};

/// D-Bus service for Rosenpass NetworkManager plugin
pub struct RosenpassDBusService {
    /// Connection manager
    manager: Arc<RosenpassConnectionManager>,
}

impl RosenpassDBusService {
    /// Create a new D-Bus service
    pub fn new(manager: Arc<RosenpassConnectionManager>) -> Self {
        Self { manager }
    }
}

#[interface(name = "eu.rosenpass.NetworkManager.Plugin")]
impl RosenpassDBusService {
    /// Activate a Rosenpass connection
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the NetworkManager connection to activate
    /// 
    /// # Returns
    /// * Success or error message
    async fn activate_connection(
        &self,
        connection_uuid: String,
    ) -> zbus::fdo::Result<()> {
        log::info!("D-Bus request to activate connection: {}", connection_uuid);
        
        self.manager
            .activate_connection(&connection_uuid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        log::info!("Successfully activated connection: {}", connection_uuid);
        Ok(())
    }
    
    /// Deactivate a Rosenpass connection
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the NetworkManager connection to deactivate
    /// 
    /// # Returns
    /// * Success or error message
    async fn deactivate_connection(
        &self,
        connection_uuid: String,
    ) -> zbus::fdo::Result<()> {
        log::info!("D-Bus request to deactivate connection: {}", connection_uuid);
        
        self.manager
            .deactivate_connection(&connection_uuid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        log::info!("Successfully deactivated connection: {}", connection_uuid);
        Ok(())
    }
    
    /// Get the status of a connection
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the NetworkManager connection
    /// 
    /// # Returns
    /// * Connection status string
    async fn get_connection_status(
        &self,
        connection_uuid: String,
    ) -> zbus::fdo::Result<String> {
        log::debug!("D-Bus request for connection status: {}", connection_uuid);
        
        let status = self.manager
            .get_connection_status(&connection_uuid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        Ok(status.to_string())
    }
    
    /// List all managed connections
    /// 
    /// # Returns
    /// * Array of connection UUIDs
    async fn list_connections(&self) -> zbus::fdo::Result<Vec<String>> {
        log::debug!("D-Bus request to list connections");
        
        let connections = self.manager.list_connections().await;
        Ok(connections.into_iter().map(|uuid| uuid.to_string()).collect())
    }
    
    /// Add a new connection configuration
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the NetworkManager connection
    /// * `config_path` - Path to the Rosenpass configuration file
    /// 
    /// # Returns
    /// * Success or error message
    async fn add_connection(
        &self,
        connection_uuid: String,
        config_path: String,
    ) -> zbus::fdo::Result<()> {
        log::info!("D-Bus request to add connection: {} with config: {}", 
                  connection_uuid, config_path);
        
        self.manager
            .add_connection(&connection_uuid, &config_path.into())
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        log::info!("Successfully added connection: {}", connection_uuid);
        Ok(())
    }
    
    /// Remove a connection configuration
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the NetworkManager connection to remove
    /// 
    /// # Returns
    /// * Success or error message
    async fn remove_connection(
        &self,
        connection_uuid: String,
    ) -> zbus::fdo::Result<()> {
        log::info!("D-Bus request to remove connection: {}", connection_uuid);
        
        self.manager
            .remove_connection(&connection_uuid)
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        log::info!("Successfully removed connection: {}", connection_uuid);
        Ok(())
    }
    
    /// Reload configuration files
    /// 
    /// # Returns
    /// * Success or error message
    async fn reload_configuration(&self) -> zbus::fdo::Result<()> {
        log::info!("D-Bus request to reload configuration");
        
        self.manager
            .reload_configuration()
            .await
            .map_err(|e| zbus::fdo::Error::Failed(e.to_string()))?;
        
        log::info!("Successfully reloaded configuration");
        Ok(())
    }
    
    /// Get plugin version information
    /// 
    /// # Returns
    /// * Version string
    async fn get_version(&self) -> zbus::fdo::Result<String> {
        Ok(crate::VERSION.to_string())
    }
    
    /// Signal emitted when a connection state changes
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the connection
    /// * `state` - New connection state
    #[zbus(signal)]
    pub async fn connection_state_changed(
        ctxt: &SignalContext<'_>,
        connection_uuid: &str,
        state: &str,
    ) -> zbus::Result<()>;
    
    /// Signal emitted when an error occurs
    /// 
    /// # Arguments
    /// * `connection_uuid` - UUID of the connection (if applicable)
    /// * `error_message` - Error description
    #[zbus(signal)]
    pub async fn error_occurred(
        ctxt: &SignalContext<'_>,
        connection_uuid: &str,
        error_message: &str,
    ) -> zbus::Result<()>;
}

/// Helper struct for managing D-Bus signals
pub struct DBusSignalEmitter {
    connection: zbus::Connection,
}

impl DBusSignalEmitter {
    /// Create a new signal emitter
    pub fn new(connection: zbus::Connection) -> Self {
        Self {
            connection,
        }
    }
    
    /// Emit a connection state changed signal
    pub async fn emit_connection_state_changed(
        &self,
        connection_uuid: &str,
        state: &str,
    ) -> Result<(), RosenpassNetworkManagerError> {
        let ctxt = SignalContext::new(&self.connection, crate::DBUS_OBJECT_PATH)?;
        
        RosenpassDBusService::connection_state_changed(
            &ctxt,
            connection_uuid,
            state,
        ).await?;
        
        Ok(())
    }
    
    /// Emit an error occurred signal
    pub async fn emit_error_occurred(
        &self,
        connection_uuid: &str,
        error_message: &str,
    ) -> Result<(), RosenpassNetworkManagerError> {
        let ctxt = SignalContext::new(&self.connection, crate::DBUS_OBJECT_PATH)?;
        
        RosenpassDBusService::error_occurred(
            &ctxt,
            connection_uuid,
            error_message,
        ).await?;
        
        Ok(())
    }
}