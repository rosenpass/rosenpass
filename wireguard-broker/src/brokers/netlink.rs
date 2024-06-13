#![cfg(target_os = "linux")]

use std::fmt::Debug;

use wireguard_uapi::linux as wg;

use crate::api::config::NetworkBrokerConfig;
use crate::api::msgs;
use crate::{SerializedBrokerConfig, WireGuardBroker};

#[derive(thiserror::Error, Debug)]
pub enum ConnectError {
    #[error(transparent)]
    ConnectError(#[from] wg::err::ConnectError),
}

#[derive(thiserror::Error, Debug)]
pub enum NetlinkError {
    #[error(transparent)]
    SetDevice(#[from] wg::err::SetDeviceError),
    #[error(transparent)]
    GetDevice(#[from] wg::err::GetDeviceError),
}

#[derive(thiserror::Error, Debug)]
pub enum SetPskError {
    #[error("The indicated wireguard interface does not exist")]
    NoSuchInterface,
    #[error("The indicated peer does not exist on the wireguard interface")]
    NoSuchPeer,
    #[error(transparent)]
    NetlinkError(#[from] NetlinkError),
}

impl From<wg::err::SetDeviceError> for SetPskError {
    fn from(err: wg::err::SetDeviceError) -> Self {
        NetlinkError::from(err).into()
    }
}

impl From<wg::err::GetDeviceError> for SetPskError {
    fn from(err: wg::err::GetDeviceError) -> Self {
        NetlinkError::from(err).into()
    }
}

use msgs::SetPskError as SetPskMsgsError;
use SetPskError as SetPskNetlinkError;
impl From<SetPskNetlinkError> for SetPskMsgsError {
    fn from(err: SetPskError) -> Self {
        match err {
            SetPskNetlinkError::NoSuchPeer => SetPskMsgsError::NoSuchPeer,
            _ => SetPskMsgsError::InternalError,
        }
    }
}

pub struct NetlinkWireGuardBroker {
    sock: wg::WgSocket,
}

impl NetlinkWireGuardBroker {
    pub fn new() -> Result<Self, ConnectError> {
        let sock = wg::WgSocket::connect()?;
        Ok(Self { sock })
    }
}

impl Debug for NetlinkWireGuardBroker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        //TODO: Add useful info in Debug
        f.debug_struct("NetlinkWireGuardBroker").finish()
    }
}

impl WireGuardBroker for NetlinkWireGuardBroker {
    type Error = SetPskError;

    fn set_psk(&mut self, config: SerializedBrokerConfig) -> Result<(), Self::Error> {
        let config: NetworkBrokerConfig = config
            .try_into()
            .map_err(|_e| SetPskError::NoSuchInterface)?;
        // Ensure that the peer exists by querying the device configuration
        // TODO: Use InvalidInterfaceError

        let state = self
            .sock
            .get_device(wg::DeviceInterface::from_name(config.iface))?;

        if state
            .peers
            .iter()
            .find(|p| &p.public_key == &config.peer_id.value)
            .is_none()
        {
            return Err(SetPskError::NoSuchPeer);
        }

        // Peer update description
        let mut set_peer = wireguard_uapi::set::Peer::from_public_key(&config.peer_id);
        set_peer
            .flags
            .push(wireguard_uapi::linux::set::WgPeerF::UpdateOnly);
        set_peer.preshared_key = Some(&config.psk.secret());

        // Device update description
        let mut set_dev = wireguard_uapi::set::Device::from_ifname(config.iface);
        set_dev.peers.push(set_peer);

        self.sock.set_device(set_dev)?;

        Ok(())
    }
}
