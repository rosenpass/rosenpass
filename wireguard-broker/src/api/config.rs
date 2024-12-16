//! This module provides [NetworkBrokerConfig] for configuring a
//! [BrokerServer](crate::api::server::BrokerServer) and tooling to serialize and deserialize these
//! configurations.

use crate::{SerializedBrokerConfig, WG_KEY_LEN, WG_PEER_LEN};
use derive_builder::Builder;
use rosenpass_secret_memory::{Public, Secret};

#[derive(Builder, Debug)]
#[builder(pattern = "mutable")]
//TODO: Use generics for iface, add additional params
/// Specifies a configuration for a [BrokerServer](crate::api::server::BrokerServer).
pub struct NetworkBrokerConfig<'a> {
    /// The interface for the [BrokerServer](crate::api::server::BrokerServer).
    pub iface: &'a str,
    /// The peer identifier for the [BrokerServer](crate::api::server::BrokerServer).
    pub peer_id: &'a Public<WG_PEER_LEN>,
    /// The pre-shared key for the [BrokerServer](crate::api::server::BrokerServer) and the
    /// interface.
    pub psk: &'a Secret<WG_KEY_LEN>,
}

impl<'a> From<NetworkBrokerConfig<'a>> for SerializedBrokerConfig<'a> {
    /// Transforms a [NetworkBrokerConfig] into a [SerializedBrokerConfig] meant for serialization.
    fn from(src: NetworkBrokerConfig<'a>) -> SerializedBrokerConfig<'a> {
        Self {
            interface: src.iface.as_bytes(),
            peer_id: src.peer_id,
            psk: src.psk,
            additional_params: &[],
        }
    }
}

/// Error variants that can occur when loading a [NetworkBrokerConfig] from a
/// [SerializedBrokerConfig].
#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum NetworkBrokerConfigErr {
    /// Error indicating that the interface specification could not be read correctly.
    #[error("Interface")]
    Interface, // TODO, give this a better name.
}

impl<'a> TryFrom<SerializedBrokerConfig<'a>> for NetworkBrokerConfig<'a> {
    type Error = NetworkBrokerConfigErr;

    /// Tries to load a [NetworkBrokerConfig] from a [SerializedBrokerConfig].
    ///
    /// # Errors
    /// Returns a [NetworkBrokerConfigErr::Interface]-error when the interface description
    /// can not be parsed correctly.
    fn try_from(value: SerializedBrokerConfig<'a>) -> Result<Self, Self::Error> {
        let iface =
            std::str::from_utf8(value.interface).map_err(|_| NetworkBrokerConfigErr::Interface)?;
        Ok(Self {
            iface,
            peer_id: value.peer_id,
            psk: value.psk,
        })
    }
}
