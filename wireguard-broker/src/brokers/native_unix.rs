//! Native Unix implementation of the WireGuard PSK broker using the `wg` command-line tool.
//!
//! This module provides an implementation that works on Unix systems by executing the `wg`
//! command-line tool to set pre-shared keys. It requires the `wg` tool to be installed and
//! accessible in the system PATH.
//!
//! # Examples
//!
//! ```no_run
//! use rosenpass_secret_memory::{Public, Secret};
//! use rosenpass_wireguard_broker::brokers::native_unix::{NativeUnixBroker, NativeUnixBrokerConfigBase};
//! use rosenpass_wireguard_broker::{WireGuardBroker, WireguardBrokerCfg, WG_KEY_LEN, WG_PEER_LEN};
//!
//! # fn main() -> Result<(), anyhow::Error> {
//! // Create a broker instance
//! let mut broker = NativeUnixBroker::new();
//!
//! // Create configuration
//! let config = NativeUnixBrokerConfigBase {
//!     interface: "wg0".to_string(),
//!     peer_id: Public::zero(), // Replace with actual peer ID
//!     extra_params: Vec::new(),
//! };
//!
//! // Set PSK using the broker
//! let psk = Secret::<WG_KEY_LEN>::zero(); // Replace with actual PSK
//! let serialized_config = config.create_config(&psk);
//! broker.set_psk(serialized_config)?;
//! # Ok(())
//! # }
//! ```

use std::fmt::Debug;
use std::process::{Command, Stdio};
use std::thread;

use derive_builder::Builder;
use log::{debug, error};
use postcard::{from_bytes, to_allocvec};
use rosenpass_secret_memory::{Public, Secret};
use rosenpass_to::{ops::copy_slice, To};
use rosenpass_util::b64::b64_decode;
use rosenpass_util::{b64::B64Display, file::StoreValueB64Writer};

use crate::{SerializedBrokerConfig, WireGuardBroker, WireguardBrokerCfg, WireguardBrokerMio};
use crate::{WG_KEY_LEN, WG_PEER_LEN};

/// Maximum size of a base64-encoded WireGuard key in bytes
const MAX_B64_KEY_SIZE: usize = WG_KEY_LEN * 5 / 3;
/// Maximum size of a base64-encoded WireGuard peer ID in bytes
const MAX_B64_PEER_ID_SIZE: usize = WG_PEER_LEN * 5 / 3;

/// A WireGuard broker implementation that uses the native `wg` command-line tool.
///
/// This broker executes the `wg` command to set pre-shared keys. It supports both synchronous
/// operations through the `WireGuardBroker` trait and asynchronous operations through the
/// `WireguardBrokerMio` trait.
///
/// # Requirements
///
/// - The `wg` command-line tool must be installed and in the system PATH
/// - The user running the broker must have sufficient permissions to execute `wg` commands
#[derive(Debug)]
pub struct NativeUnixBroker {
    mio_token: Option<mio::Token>,
}

impl Default for NativeUnixBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeUnixBroker {
    pub fn new() -> Self {
        Self { mio_token: None }
    }
}

impl WireGuardBroker for NativeUnixBroker {
    type Error = anyhow::Error;

    fn set_psk(&mut self, config: SerializedBrokerConfig<'_>) -> Result<(), Self::Error> {
        let config: NativeUnixBrokerConfig = config.try_into()?;

        let peer_id = format!("{}", config.peer_id.fmt_b64::<MAX_B64_PEER_ID_SIZE>());

        let mut child = match Command::new("wg")
            .arg("set")
            .arg(config.interface)
            .arg("peer")
            .arg(peer_id)
            .arg("preshared-key")
            .arg("/dev/stdin")
            .stdin(Stdio::piped())
            .args(config.extra_params)
            .spawn()
        {
            Ok(x) => x,
            Err(e) => {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow::bail!("Could not find wg command");
                } else {
                    return Err(anyhow::Error::new(e));
                }
            }
        };
        if let Err(e) = config
            .psk
            .store_b64_writer::<MAX_B64_KEY_SIZE, _>(child.stdin.take().unwrap())
        {
            error!("could not write psk to wg: {:?}", e);
        }

        thread::spawn(move || {
            let status = child.wait();

            if let Ok(status) = status {
                if status.success() {
                    debug!("successfully passed psk to wg")
                } else {
                    error!("could not pass psk to wg {:?}", status)
                }
            } else {
                error!("wait failed: {:?}", status)
            }
        });
        Ok(())
    }
}

impl WireguardBrokerMio for NativeUnixBroker {
    type MioError = anyhow::Error;

    fn register(
        &mut self,
        _registry: &mio::Registry,
        token: mio::Token,
    ) -> Result<(), Self::MioError> {
        self.mio_token = Some(token);
        Ok(())
    }

    fn process_poll(&mut self) -> Result<(), Self::MioError> {
        Ok(())
    }

    fn unregister(&mut self, _registry: &mio::Registry) -> Result<(), Self::MioError> {
        self.mio_token = None;
        Ok(())
    }

    fn mio_token(&self) -> Option<mio::Token> {
        self.mio_token
    }
}

/// Base configuration for the native Unix WireGuard broker.
///
/// This configuration type is used to store persistent broker settings and create
/// serialized configurations for individual PSK operations.
///
/// # Examples
///
/// ```
/// use rosenpass_wireguard_broker::brokers::native_unix::NativeUnixBrokerConfigBase;
/// use rosenpass_secret_memory::Public;
/// use rosenpass_wireguard_broker::WG_PEER_LEN;
///
/// let config = NativeUnixBrokerConfigBase {
///     interface: "wg0".to_string(),
///     peer_id: Public::zero(),
///     extra_params: Vec::new(),
/// };
/// ```
#[derive(Debug, Builder)]
#[builder(pattern = "mutable")]
pub struct NativeUnixBrokerConfigBase {
    /// Name of the WireGuard interface (e.g., "wg0")
    pub interface: String,
    /// Public key of the peer
    pub peer_id: Public<WG_PEER_LEN>,
    /// Additional parameters to pass to the wg command
    #[builder(private)]
    pub extra_params: Vec<u8>,
}

impl NativeUnixBrokerConfigBaseBuilder {
    /// Sets the peer ID from a base64-encoded string.
    ///
    /// # Arguments
    ///
    /// * `peer_id` - Base64-encoded peer public key
    ///
    /// # Examples
    ///
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use rosenpass_wireguard_broker::brokers::native_unix::{NativeUnixBrokerConfigBaseBuilder};
    /// let mut peer_cfg = NativeUnixBrokerConfigBaseBuilder::default();
    /// // set peer id to [48;32] encoded as base64
    /// peer_cfg.peer_id_b64("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA=")?;
    /// peer_cfg.interface("wg0".to_string());
    /// peer_cfg.extra_params_ser(&vec![])?;
    /// let peer_cfg = peer_cfg.build()?;
    /// assert_eq!(peer_cfg.peer_id.value, [48u8;32]);
    ///
    /// let error = NativeUnixBrokerConfigBaseBuilder::default()
    /// .peer_id_b64("MDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDA") // invalid base64 encoding
    /// .err().unwrap();
    /// assert_eq!(error.to_string(), "Failed to parse peer id b64");
    /// # Ok(())
    /// # }
    /// ```
    pub fn peer_id_b64(
        &mut self,
        peer_id: &str,
    ) -> Result<&mut Self, NativeUnixBrokerConfigBaseBuilderError> {
        let mut peer_id_b64 = Public::<WG_PEER_LEN>::zero();
        b64_decode(peer_id.as_bytes())
            .to(&mut peer_id_b64.value)
            .map_err(|_| {
                NativeUnixBrokerConfigBaseBuilderError::ValidationError(
                    "Failed to parse peer id b64".to_string(),
                )
            })?;
        Ok(self.peer_id(peer_id_b64))
    }

    /// Sets additional parameters for the wg command.
    ///
    /// Note: This function cannot fail as `Vec<String>` is always serializable.
    ///
    /// # Examples
    /// ```
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use rosenpass_wireguard_broker::brokers::native_unix::NativeUnixBrokerConfigBaseBuilder;
    ///
    /// let mut peer_cfg = NativeUnixBrokerConfigBaseBuilder::default();
    /// // Set typical wireguard parameters
    /// peer_cfg.interface("wg0".to_string());
    /// peer_cfg.peer_id_b64("Zm9v")?;
    /// peer_cfg.extra_params_ser(&vec![
    ///     "persistent-keepalive".to_string(),
    ///     "25".to_string(),
    ///     "allowed-ips".to_string(),
    ///     "10.0.0.2/32".to_string(),
    /// ])?;
    /// let peer_cfg = peer_cfg.build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn extra_params_ser(
        &mut self,
        extra_params: &Vec<String>,
    ) -> Result<&mut Self, NativeUnixBrokerConfigBuilderError> {
        let params = to_allocvec(extra_params).map_err(|_e| {
            NativeUnixBrokerConfigBuilderError::ValidationError(
                "Failed to parse extra params".to_string(),
            )
        })?;
        Ok(self.extra_params(params))
    }
}

impl WireguardBrokerCfg for NativeUnixBrokerConfigBase {
    fn create_config<'a>(&'a self, psk: &'a Secret<WG_KEY_LEN>) -> SerializedBrokerConfig<'a> {
        SerializedBrokerConfig {
            interface: self.interface.as_bytes(),
            peer_id: &self.peer_id,
            psk,
            additional_params: &self.extra_params,
        }
    }
}

/// Runtime configuration for a single PSK operation.
#[derive(Debug, Builder)]
#[builder(pattern = "mutable")]
pub struct NativeUnixBrokerConfig<'a> {
    /// WireGuard interface name
    pub interface: &'a str,
    /// Public key of the peer
    pub peer_id: &'a Public<WG_PEER_LEN>,
    /// Pre-shared key to set
    pub psk: &'a Secret<WG_KEY_LEN>,
    /// Additional wg command parameters
    pub extra_params: Vec<String>,
}

impl<'a> TryFrom<SerializedBrokerConfig<'a>> for NativeUnixBrokerConfig<'a> {
    type Error = anyhow::Error;

    fn try_from(value: SerializedBrokerConfig<'a>) -> Result<Self, Self::Error> {
        let iface = std::str::from_utf8(value.interface)
            .map_err(|_| anyhow::Error::msg("Interface UTF8 decoding error"))?;

        let extra_params: Vec<String> =
            from_bytes(value.additional_params).map_err(anyhow::Error::new)?;
        Ok(Self {
            interface: iface,
            peer_id: value.peer_id,
            psk: value.psk,
            extra_params,
        })
    }
}
