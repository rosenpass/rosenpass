//! Error types for the NetworkManager plugin

use thiserror::Error;

/// Errors that can occur in the NetworkManager plugin
#[derive(Error, Debug)]
pub enum RosenpassNetworkManagerError {
    /// Configuration file error
    #[error("Configuration error: {0}")]
    Config(#[from] toml::de::Error),

    /// D-Bus communication error
    #[error("D-Bus error: {0}")]
    DBus(#[from] zbus::Error),

    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// Rosenpass connection error
    #[error("Rosenpass error: {0}")]
    Rosenpass(#[from] anyhow::Error),

    /// Connection not found
    #[error("Connection not found: {0}")]
    ConnectionNotFound(String),

    /// Invalid connection UUID
    #[error("Invalid connection UUID: {0}")]
    InvalidUuid(String),

    /// Connection already active
    #[error("Connection already active: {0}")]
    ConnectionActive(String),

    /// Connection not active
    #[error("Connection not active: {0}")]
    ConnectionInactive(String),

    /// Key exchange failed
    #[error("Key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// WireGuard broker error
    #[error("WireGuard broker error: {0}")]
    WireGuardBroker(String),
}

/// Result type for NetworkManager plugin operations
pub type Result<T> = std::result::Result<T, RosenpassNetworkManagerError>;