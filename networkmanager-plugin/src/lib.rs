//! NetworkManager plugin for Rosenpass post-quantum key exchange
//!
//! This crate provides a NetworkManager plugin that integrates Rosenpass
//! post-quantum secure key exchange with NetworkManager's D-Bus interface.

pub mod config;
pub mod simple_connection;
pub mod dbus_service;
pub mod manager;
pub mod error;

pub use config::RosenpassConfig;
pub use simple_connection::SimpleRosenpassConnection;
pub use dbus_service::RosenpassDBusService;
pub use manager::RosenpassConnectionManager;
pub use error::RosenpassNetworkManagerError;

/// NetworkManager plugin version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// D-Bus service name for the Rosenpass NetworkManager plugin
pub const DBUS_SERVICE_NAME: &str = "eu.rosenpass.NetworkManager";

/// D-Bus object path for the plugin
pub const DBUS_OBJECT_PATH: &str = "/eu/rosenpass/NetworkManager";

/// D-Bus interface name
pub const DBUS_INTERFACE_NAME: &str = "eu.rosenpass.NetworkManager.Plugin";