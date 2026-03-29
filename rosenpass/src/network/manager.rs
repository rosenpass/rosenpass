use std::error::Error;

use super::{connman::ConnManManager, NetworkManager, NetworkState, NetworkTechnology};

/// Default network manager implementation that uses ConnMan
pub struct DefaultNetworkManager {
    connman: Option<ConnManManager>,
}

impl DefaultNetworkManager {
    /// Create a new default network manager
    pub fn new() -> Self {
        Self { connman: None }
    }
}

impl Default for DefaultNetworkManager {
    fn default() -> Self {
        Self::new()
    }
}

impl NetworkManager for DefaultNetworkManager {
    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        if self.connman.is_none() {
            let connman = tokio::runtime::Runtime::new()?
                .block_on(async { ConnManManager::new().await })?;
            self.connman = Some(connman);
        }
        Ok(())
    }

    fn get_state(&self) -> Result<NetworkState, Box<dyn Error>> {
        match &self.connman {
            Some(connman) => Ok(tokio::runtime::Runtime::new()?.block_on(async {
                connman.get_state().await
            })?),
            None => Err("Network manager not initialized".into()),
        }
    }

    fn get_technologies(&self) -> Result<Vec<NetworkTechnology>, Box<dyn Error>> {
        match &self.connman {
            Some(connman) => Ok(tokio::runtime::Runtime::new()?.block_on(async {
                connman.get_technologies().await
            })?),
            None => Err("Network manager not initialized".into()),
        }
    }

    fn get_services(&self) -> Result<Vec<String>, Box<dyn Error>> {
        match &self.connman {
            Some(connman) => Ok(tokio::runtime::Runtime::new()?.block_on(async {
                connman.get_services().await
            })?),
            None => Err("Network manager not initialized".into()),
        }
    }

    fn connect_service(&self, service_name: &str) -> Result<(), Box<dyn Error>> {
        match &self.connman {
            Some(connman) => Ok(tokio::runtime::Runtime::new()?.block_on(async {
                connman.connect_service(service_name).await
            })?),
            None => Err("Network manager not initialized".into()),
        }
    }
}