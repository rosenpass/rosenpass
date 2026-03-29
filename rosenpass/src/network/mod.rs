use std::error::Error;

pub mod connman;

/// Network manager trait that can be implemented by different network managers
pub trait NetworkManager {
    /// Initialize the network manager
    fn init(&mut self) -> Result<(), Box<dyn Error>>;

    /// Get current network state
    fn get_state(&self) -> Result<NetworkState, Box<dyn Error>>;

    /// Get available network technologies
    fn get_technologies(&self) -> Result<Vec<NetworkTechnology>, Box<dyn Error>>;

    /// Get list of available services
    fn get_services(&self) -> Result<Vec<String>, Box<dyn Error>>;

    /// Connect to a specific service
    fn connect_service(&self, service_name: &str) -> Result<(), Box<dyn Error>>;
}

/// Re-export network types
pub use connman::{NetworkState, NetworkTechnology};