//! A broker interface for managing WireGuard pre-shared keys (PSK).
//!
//! This crate provides traits and implementations for interacting with WireGuard interfaces
//! to set pre-shared keys for peers. It supports different backend implementations including:
//! - Native Unix command-line interface
//! - Linux netlink interface
//! - Custom Unix socket protocol
//!
//! # Examples
//!
//! ```no_run
//! # use rosenpass_secret_memory::{Public, Secret};
//! # use rosenpass_wireguard_broker::{WireGuardBroker, SerializedBrokerConfig, WG_KEY_LEN, WG_PEER_LEN};
//! # use std::error::Error;
//!
//! # fn main() -> Result<(), Box<dyn Error>> {
//! # rosenpass_secret_memory::policy::secret_policy_try_use_memfd_secrets();
//! # let interface = "wg0";
//! # let peer_id = Public::<WG_PEER_LEN>::zero();
//! # let psk = Secret::<WG_KEY_LEN>::zero();
//!
//! // Create a native Unix broker
//! let mut broker = rosenpass_wireguard_broker::brokers::native_unix::NativeUnixBroker::new();
//!
//! // Configure and set PSK
//! let config = SerializedBrokerConfig {
//!     interface: interface.as_bytes(),
//!     peer_id: &peer_id,
//!     psk: &psk,
//!     additional_params: &[],
//! };
//!
//! broker.set_psk(config)?;
//! # Ok(())
//! # }
//! ```

use rosenpass_secret_memory::{Public, Secret};
use std::fmt::Debug;

/// Length of a WireGuard key in bytes
pub const WG_KEY_LEN: usize = 32;

/// Length of a WireGuard peer ID in bytes
pub const WG_PEER_LEN: usize = 32;

/// Core trait for WireGuard PSK brokers.
///
/// This trait defines the basic interface for setting pre-shared keys (PSK) on WireGuard interfaces.
/// Implementations handle the actual communication with WireGuard, whether through command-line tools,
/// netlink, or other mechanisms.
pub trait WireGuardBroker: Debug {
    /// The error type returned by broker operations
    type Error;

    /// Set a pre-shared key for a WireGuard peer
    fn set_psk(&mut self, config: SerializedBrokerConfig<'_>) -> Result<(), Self::Error>;
}

/// Configuration trait for WireGuard PSK brokers.
///
/// This trait allows creation of broker configurations from a PSK and implementation-specific
/// configuration data.
pub trait WireguardBrokerCfg: Debug {
    /// Creates a serialized broker configuration from this config and a specific PSK
    fn create_config<'a>(&'a self, psk: &'a Secret<WG_KEY_LEN>) -> SerializedBrokerConfig<'a>;
}

/// Serialized configuration for WireGuard PSK operations.
#[derive(Debug)]
pub struct SerializedBrokerConfig<'a> {
    /// The WireGuard interface name as UTF-8 bytes
    pub interface: &'a [u8],
    /// The public key of the peer
    pub peer_id: &'a Public<WG_PEER_LEN>,
    /// The pre-shared key to set
    pub psk: &'a Secret<WG_KEY_LEN>,
    /// Additional implementation-specific parameters
    pub additional_params: &'a [u8],
}

/// Extension trait for mio integration with WireGuard brokers.
///
/// This trait extends the basic `WireGuardBroker` functionality with asynchronous I/O
/// operations using the mio event framework.
pub trait WireguardBrokerMio: WireGuardBroker {
    /// The error type for mio operations
    type MioError;

    /// Register the broker with a mio Registry for event notifications
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
    ) -> Result<(), Self::MioError>;

    /// Get the mio token associated with this broker, if any
    fn mio_token(&self) -> Option<mio::Token>;

    /// Process events after a mio poll operation
    fn process_poll(&mut self) -> Result<(), Self::MioError>;

    /// Unregister the broker from a mio Registry
    fn unregister(&mut self, registry: &mio::Registry) -> Result<(), Self::MioError>;
}

#[cfg(feature = "experiment_api")]
pub mod api;

pub mod brokers;
