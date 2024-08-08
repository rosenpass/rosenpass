use std::str::{from_utf8, Utf8Error};

use zerocopy::{AsBytes, FromBytes, FromZeroes};

pub const ENVELOPE_OVERHEAD: usize = 1 + 3;
pub const REQUEST_MSG_BUFFER_SIZE: usize = ENVELOPE_OVERHEAD + 32 + 32 + 1 + 255;
pub const RESPONSE_MSG_BUFFER_SIZE: usize = ENVELOPE_OVERHEAD + 1;

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct Envelope<M: AsBytes + FromBytes> {
    /// [MsgType] of this message
    pub msg_type: u8,
    /// Reserved for future use
    pub reserved: [u8; 3],
    /// The actual Paylod
    pub payload: M,
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct SetPskRequest {
    pub peer_id: [u8; 32],
    pub psk: [u8; 32],
    pub iface_size: u8, // TODO: We should have variable length strings in lenses
    pub iface_buf: [u8; 255],
}

impl SetPskRequest {
    pub fn iface_bin(&self) -> &[u8] {
        let len = self.iface_size as usize;
        &self.iface_buf[..len]
    }

    pub fn iface(&self) -> Result<&str, Utf8Error> {
        from_utf8(self.iface_bin())
    }

    pub fn set_iface_bin(&mut self, iface: &[u8]) -> Option<()> {
        (iface.len() < 256).then_some(())?; // Assert iface.len() < 256

        self.iface_size = iface.len() as u8;

        self.iface_buf = [0; 255];
        self.iface_buf[..iface.len()].copy_from_slice(iface);

        Some(())
    }

    pub fn set_iface(&mut self, iface: &str) -> Option<()> {
        self.set_iface_bin(iface.as_bytes())
    }
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct SetPskResponse {
    pub return_code: u8,
}

#[derive(thiserror::Error, Debug, Clone, Eq, PartialEq)]
pub enum SetPskError {
    #[error("The wireguard pre-shared-key assignment broker experienced an internal error.")]
    InternalError,
    #[error("The indicated wireguard interface does not exist")]
    NoSuchInterface,
    #[error("The indicated peer does not exist on the wireguard interface")]
    NoSuchPeer,
}

pub type SetPskResult = Result<(), SetPskError>;

#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum SetPskResponseReturnCode {
    Success = 0x00,
    InternalError = 0x01,
    NoSuchInterface = 0x02,
    NoSuchPeer = 0x03,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct InvalidSetPskResponseError;

impl TryFrom<u8> for SetPskResponseReturnCode {
    type Error = InvalidSetPskResponseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        use SetPskResponseReturnCode::*;
        match value {
            0x00 => Ok(Success),
            0x01 => Ok(InternalError),
            0x02 => Ok(NoSuchInterface),
            0x03 => Ok(NoSuchPeer),
            _ => Err(InvalidSetPskResponseError),
        }
    }
}

impl From<SetPskResponseReturnCode> for SetPskResult {
    fn from(value: SetPskResponseReturnCode) -> Self {
        use SetPskError as E;
        use SetPskResponseReturnCode as C;
        match value {
            C::Success => Ok(()),
            C::InternalError => Err(E::InternalError),
            C::NoSuchInterface => Err(E::NoSuchInterface),
            C::NoSuchPeer => Err(E::NoSuchPeer),
        }
    }
}

impl From<SetPskResult> for SetPskResponseReturnCode {
    fn from(value: SetPskResult) -> Self {
        use SetPskError as E;
        use SetPskResponseReturnCode as C;
        match value {
            Ok(()) => C::Success,
            Err(E::InternalError) => C::InternalError,
            Err(E::NoSuchInterface) => C::NoSuchInterface,
            Err(E::NoSuchPeer) => C::NoSuchPeer,
        }
    }
}

#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum MsgType {
    SetPsk = 0x01,
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub struct InvalidMessageTypeError;

impl TryFrom<u8> for MsgType {
    type Error = InvalidMessageTypeError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MsgType::SetPsk),
            _ => Err(InvalidMessageTypeError),
        }
    }
}
