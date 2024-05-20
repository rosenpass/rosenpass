use crate::{SerializedBrokerConfig, WG_KEY_LEN, WG_PEER_LEN};
use derive_builder::Builder;
use rosenpass_secret_memory::{Public, Secret};

#[derive(Builder)]
#[builder(pattern = "mutable")]
//TODO: Use generics for iface, add additional params
pub struct NetworkBrokerConfig<'a> {
    pub iface: &'a str,
    pub peer_id: &'a Public<WG_PEER_LEN>,
    pub psk: &'a Secret<WG_KEY_LEN>,
}

impl<'a> Into<SerializedBrokerConfig<'a>> for NetworkBrokerConfig<'a> {
    fn into(self) -> SerializedBrokerConfig<'a> {
        SerializedBrokerConfig {
            interface: self.iface.as_bytes(),
            peer_id: self.peer_id,
            psk: self.psk,
            additional_params: &[],
        }
    }
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum NetworkBrokerConfigErr {
    #[error("Interface")]
    Interface,
}

impl<'a> TryFrom<SerializedBrokerConfig<'a>> for NetworkBrokerConfig<'a> {
    type Error = NetworkBrokerConfigErr;

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
