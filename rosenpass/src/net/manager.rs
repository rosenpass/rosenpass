use std::fmt;

use anyhow::Context;
use thiserror::Error;

#[cfg(feature = "netctl")]
use super::netctl;

/// Network manager types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkManagerType {
    Systemd,
    Netctl,
    None,
}

impl fmt::Display for NetworkManagerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NetworkManagerType::Systemd => write!(f, "systemd-networkd"),
            NetworkManagerType::Netctl => write!(f, "netctl"),
            NetworkManagerType::None => write!(f, "none"),
        }
    }
}

/// Network manager interface
pub trait NetworkManager {
    /// Start the network service
    fn start_service(&self, service_name: &str) -> anyhow::Result<()>;

    /// Stop the network service
    fn stop_service(&self, service_name: &str) -> anyhow::Result<()>;

    /// Check if a service is active
    fn is_service_active(&self, service_name: &str) -> anyhow::Result<bool>;
}

/// Detect which network manager is available
pub fn detect_network_manager() -> NetworkManagerType {
    #[cfg(feature = "netctl")]
    {
        if netctl::is_netctl_available() {
            return NetworkManagerType::Netctl;
        }
    }

    NetworkManagerType::Systemd
}

/// Create a network manager instance based on the detected type
pub fn create_network_manager() -> Box<dyn NetworkManager> {
    match detect_network_manager() {
        NetworkManagerType::Systemd => Box::new(SystemdNetworkManager),
        NetworkManagerType::Netctl => Box::new(NetctlNetworkManager),
        NetworkManagerType::None => Box::new(NoOpNetworkManager),
    }
}

/// Systemd network manager implementation
struct SystemdNetworkManager;

impl NetworkManager for SystemdNetworkManager {
    fn start_service(&self, service_name: &str) -> anyhow::Result<()> {
        std::process::Command::new("systemctl")
            .arg("start")
            .arg(service_name)
            .status()
            .with_context(|| format!("Failed to start service {}", service_name))?;
        Ok(())
    }

    fn stop_service(&self, service_name: &str) -> anyhow::Result<()> {
        std::process::Command::new("systemctl")
            .arg("stop")
            .arg(service_name)
            .status()
            .with_context(|| format!("Failed to stop service {}", service_name))?;
        Ok(())
    }

    fn is_service_active(&self, service_name: &str) -> anyhow::Result<bool> {
        let output = std::process::Command::new("systemctl")
            .arg("is-active")
            .arg(service_name)
            .output()
            .with_context(|| format!("Failed to check status of service {}", service_name))?;

        Ok(output.status.success() && String::from_utf8_lossy(&output.stdout)
            .trim()
            .eq_ignore_ascii_case("active"))
    }
}

/// Netctl network manager implementation
#[cfg(feature = "netctl")]
struct NetctlNetworkManager;

#[cfg(feature = "netctl")]
impl NetworkManager for NetctlNetworkManager {
    fn start_service(&self, service_name: &str) -> anyhow::Result<()> {
        netctl::start_service(service_name)
            .map_err(|e| anyhow::anyhow!("Failed to start service {}: {}", service_name, e))
    }

    fn stop_service(&self, service_name: &str) -> anyhow::Result<()> {
        netctl::stop_service(service_name)
            .map_err(|e| anyhow::anyhow!("Failed to stop service {}: {}", service_name, e))
    }

    fn is_service_active(&self, service_name: &str) -> anyhow::Result<bool> {
        netctl::is_service_active(service_name)
            .map_err(|e| anyhow::anyhow!("Failed to check status of service {}: {}", service_name, e))
    }
}

/// No-op network manager for systems without network management
struct NoOpNetworkManager;

impl NetworkManager for NoOpNetworkManager {
    fn start_service(&self, _service_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn stop_service(&self, _service_name: &str) -> anyhow::Result<()> {
        Ok(())
    }

    fn is_service_active(&self, _service_name: &str) -> anyhow::Result<bool> {
        Ok(false)
    }
}