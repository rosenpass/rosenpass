use std::fmt::Debug;
use std::process::{Command, Stdio};
use std::thread;

use derive_builder::Builder;
use log::{debug, error};
use postcard::{from_bytes, to_allocvec};
use rosenpass_secret_memory::{Public, Secret};
use rosenpass_util::b64::b64_decode;
use rosenpass_util::{b64::B64Display, file::StoreValueB64Writer};

use crate::{SerializedBrokerConfig, WireGuardBroker, WireguardBrokerCfg, WireguardBrokerMio};
use crate::{WG_KEY_LEN, WG_PEER_LEN};

const MAX_B64_KEY_SIZE: usize = WG_KEY_LEN * 5 / 3;
const MAX_B64_PEER_ID_SIZE: usize = WG_PEER_LEN * 5 / 3;

#[derive(Debug)]
pub struct NativeUnixBroker {}

impl Default for NativeUnixBroker {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeUnixBroker {
    pub fn new() -> Self {
        Self {}
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
        _token: mio::Token,
    ) -> Result<(), Self::MioError> {
        Ok(())
    }

    fn process_poll(&mut self) -> Result<(), Self::MioError> {
        Ok(())
    }

    fn unregister(&mut self, _registry: &mio::Registry) -> Result<(), Self::MioError> {
        Ok(())
    }
}

#[derive(Debug, Builder)]
#[builder(pattern = "mutable")]
pub struct NativeUnixBrokerConfigBase {
    pub interface: String,
    pub peer_id: Public<WG_PEER_LEN>,
    #[builder(private)]
    pub extra_params: Vec<u8>,
}

impl NativeUnixBrokerConfigBaseBuilder {
    pub fn peer_id_b64(
        &mut self,
        peer_id: &str,
    ) -> Result<&mut Self, NativeUnixBrokerConfigBaseBuilderError> {
        let mut peer_id_b64 = Public::<WG_PEER_LEN>::zero();
        b64_decode(peer_id.as_bytes(), &mut peer_id_b64.value).map_err(|_e| {
            NativeUnixBrokerConfigBaseBuilderError::ValidationError(
                "Failed to parse peer id b64".to_string(),
            )
        })?;
        Ok(self.peer_id(peer_id_b64))
    }

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

#[derive(Debug, Builder)]
#[builder(pattern = "mutable")]
pub struct NativeUnixBrokerConfig<'a> {
    pub interface: &'a str,
    pub peer_id: &'a Public<WG_PEER_LEN>,
    pub psk: &'a Secret<WG_KEY_LEN>,
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
