use rosenpass_secret_memory::{Public, Secret};
use std::fmt::Debug;

pub const WG_KEY_LEN: usize = 32;
pub const WG_PEER_LEN: usize = 32;
pub trait WireGuardBroker: Debug {
    type Error;
    fn set_psk(&mut self, config: SerializedBrokerConfig<'_>) -> Result<(), Self::Error>;
}

pub trait WireguardBrokerCfg: Debug {
    fn create_config<'a>(&'a self, psk: &'a Secret<WG_KEY_LEN>) -> SerializedBrokerConfig<'a>;
}

#[derive(Debug)]
pub struct SerializedBrokerConfig<'a> {
    pub interface: &'a [u8],
    pub peer_id: &'a Public<WG_PEER_LEN>,
    pub psk: &'a Secret<WG_KEY_LEN>,
    pub additional_params: &'a [u8],
}

pub trait WireguardBrokerMio: WireGuardBroker {
    type MioError;
    /// Register interested events for mio::Registry
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: mio::Token,
    ) -> Result<(), Self::MioError>;
    /// Run after a mio::poll operation
    fn process_poll(&mut self) -> Result<(), Self::MioError>;

    fn unregister(&mut self, registry: &mio::Registry) -> Result<(), Self::MioError>;
}

#[cfg(feature = "experiment_broker_api")]
pub mod api;

pub mod brokers;
