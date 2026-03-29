use std::path::Path;
use std::process::Command;
use thiserror::Error;
use std::io;

/// Network manager backend types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkManagerBackend {
    SystemdNetworkd,
    // Other backends can be added here
}

/// Errors that can occur when managing the network
#[derive(Debug, Error)]
pub enum NetworkManagerError {
    #[error("Failed to execute network manager command: {0}")]
    CommandExecutionFailed(#[from] io::Error),

    #[error("Network manager command failed with exit code {0}")]
    CommandFailed(i32),

    #[error("Network configuration file error: {0}")]
    ConfigError(String),
}

/// Trait for network management operations
pub trait NetworkManager {
    /// Apply network configuration
    fn apply_config(&self, config: &str, config_path: &Path) -> Result<(), NetworkManagerError>;

    /// Reload network configuration
    fn reload(&self) -> Result<(), NetworkManagerError>;

    /// Check if the network manager is available/running
    fn is_available(&self) -> bool;
}

/// Systemd-networkd implementation of NetworkManager
#[cfg(feature = "systemd-networkd")]
pub struct SystemdNetworkdManager;

#[cfg(feature = "systemd-networkd")]
impl NetworkManager for SystemdNetworkdManager {
    fn apply_config(&self, config: &str, config_path: &Path) -> Result<(), NetworkManagerError> {
        // Write configuration to file
        std::fs::write(config_path, config)
            .map_err(|e| NetworkManagerError::ConfigError(e.to_string()))?;

        // Reload systemd-networkd to apply changes
        let status = Command::new("networkctl")
            .arg("reload")
            .status()
            .map_err(NetworkManagerError::CommandExecutionFailed)?;

        if !status.success() {
            return Err(NetworkManagerError::CommandFailed(status.code().unwrap_or(1)));
        }

        Ok(())
    }

    fn reload(&self) -> Result<(), NetworkManagerError> {
        let status = Command::new("networkctl")
            .arg("reload")
            .status()
            .map_err(NetworkManagerError::CommandExecutionFailed)?;

        if !status.success() {
            return Err(NetworkManagerError::CommandFailed(status.code().unwrap_or(1)));
        }

        Ok(())
    }

    fn is_available(&self) -> bool {
        Command::new("networkctl")
            .arg("--version")
            .output()
            .map(|output| output.status.success())
            .unwrap_or(false)
    }
}

/// Default network manager implementation (uses systemd-networkd when available)
pub struct DefaultNetworkManager {
    backend: NetworkManagerBackend,
}

impl DefaultNetworkManager {
    pub fn new() -> Self {
        #[cfg(feature = "systemd-networkd")]
        {
            let systemd = SystemdNetworkdManager;
            if systemd.is_available() {
                return Self {
                    backend: NetworkManagerBackend::SystemdNetworkd,
                };
            }
        }

        // Fallback to systemd-networkd even if feature is not enabled
        // (we'll try to use it anyway)
        Self {
            backend: NetworkManagerBackend::SystemdNetworkd,
        }
    }
}

impl NetworkManager for DefaultNetworkManager {
    fn apply_config(&self, config: &str, config_path: &Path) -> Result<(), NetworkManagerError> {
        match self.backend {
            NetworkManagerBackend::SystemdNetworkd => {
                SystemdNetworkdManager.apply_config(config, config_path)
            }
        }
    }

    fn reload(&self) -> Result<(), NetworkManagerError> {
        match self.backend {
            NetworkManagerBackend::SystemdNetworkd => SystemdNetworkdManager.reload(),
        }
    }

    fn is_available(&self) -> bool {
        match self.backend {
            NetworkManagerBackend::SystemdNetworkd => SystemdNetworkdManager.is_available(),
        }
    }
}