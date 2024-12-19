//! This module defines message formats for messages in the Wireguard Broker protocol as well as
//! helper structures like errors and conversion functions.

use std::str::{from_utf8, Utf8Error};

use zerocopy::{AsBytes, FromBytes, FromZeroes};

/// The number of bytes reserved for overhead when packaging data.
pub const ENVELOPE_OVERHEAD: usize = 1 + 3;

/// The buffer size for request messages.
pub const REQUEST_MSG_BUFFER_SIZE: usize = ENVELOPE_OVERHEAD + 32 + 32 + 1 + 255;
/// The buffer size for responses.
pub const RESPONSE_MSG_BUFFER_SIZE: usize = ENVELOPE_OVERHEAD + 1;

/// Envelope for messages being passed around.
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

/// Message format for requests to set a pre-shared key.
/// # Example
///
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct SetPskRequest {
    /// The pre-shared key.
    pub psk: [u8; 32],
    /// The identifier of the peer.
    pub peer_id: [u8; 32],
    /// The size for the interface
    pub iface_size: u8, // TODO: We should have variable length strings in lenses
    /// The buffer for the interface.
    pub iface_buf: [u8; 255],
}

impl SetPskRequest {
    /// Gets the interface specification as byte slice.
    pub fn iface_bin(&self) -> &[u8] {
        let len = self.iface_size as usize;
        &self.iface_buf[..len]
    }

    /// Gets the interface specification as a `&str`.
    ///
    /// # Errors
    /// Returns a [Utf8Error] if the interface specification isn't utf8 encoded.
    pub fn iface(&self) -> Result<&str, Utf8Error> {
        from_utf8(self.iface_bin())
    }

    /// Sets the interface specification to `iface`. No check is made whether `iface` is correctly
    /// encoded as utf8.
    ///
    /// # Result
    /// Returns [None] if `iface` is longer than 255 bytes. Otherwise, it returns
    /// [Some(())](Some).
    pub fn set_iface_bin(&mut self, iface: &[u8]) -> Option<()> {
        (iface.len() < 256).then_some(())?; // Assert iface.len() < 256

        self.iface_size = iface.len() as u8;

        self.iface_buf = [0; 255];
        self.iface_buf[..iface.len()].copy_from_slice(iface);

        Some(())
    }

    /// Sets the interface specification to `iface`.
    ///
    /// # Result
    /// Returns [None] if `iface` is longer than 255 bytes. Otherwise, it returns
    /// [Some(())](Some).
    pub fn set_iface(&mut self, iface: &str) -> Option<()> {
        self.set_iface_bin(iface.as_bytes())
    }
}

/// Message format for response to the set pre-shared key operation.
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct SetPskResponse {
    pub return_code: u8,
}

/// Error type for the errors that can occur when setting a pre-shared key.
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

/// The return codes and their meanings for the set psk response operation.
///
/// [SetPskResponseReturnCode] is represented by by a single `u8` as required by the protocol.
///
/// # Example
/// See [SetPskResponseReturnCode::try_from] for an example.
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

    /// Parse a [u8] as a [MsgType].
    ///
    /// # Example
    /// ```
    /// # use rosenpass_wireguard_broker::api::msgs::{InvalidSetPskResponseError, SetPskResponseReturnCode};
    /// let return_code: u8 = 0x00; // Usually specifically set or comes out of a message.
    /// let res = SetPskResponseReturnCode::try_from(return_code);
    /// assert!(res.is_ok());
    /// assert_eq!(res.unwrap(), SetPskResponseReturnCode::Success);
    /// # Ok::<(), InvalidSetPskResponseError>(())
    /// ```
    /// # Errors
    /// Returns a [InvalidSetPskResponseError] if `value` does not correspond to a known return code.
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
    /// A [SetPskResult] can directly be deduced from a [SetPskResponseReturnCode].
    /// An [Ok] type is only returned if `value` is [SetPskResponseReturnCode::Success].
    /// Otherwise, an appropriate variant of [SetPskError] will be returned.
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
    /// A [SetPskResponseReturnCode] can directly be deduced from a [SetPskResult].
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

/// The types of messages supported by this crate. At the time of writing, this is only
/// the message to set a pre-shared key.
///
/// [MsgType] is represented by a single `u8` as required by the protocol.
///
/// # Example
/// It is usually used like this:
/// ```
/// # use rosenpass_wireguard_broker::api::msgs::{InvalidMessageTypeError, MsgType};
/// let typ: u8 = 0x01; // Usually specifically set or comes out of a message.
/// let typ = MsgType::try_from(typ)?;
/// let MsgType::SetPsk = typ; // Assert type.
/// # Ok::<(), InvalidMessageTypeError>(())
/// ```
#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum MsgType {
    SetPsk = 0x01,
}

/// Error indicating that an invalid [MsgType] was used.
/// This error is returned by [MsgType::try_from].
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct InvalidMessageTypeError;

impl TryFrom<u8> for MsgType {
    type Error = InvalidMessageTypeError;

    /// Parse a [u8] as a [MsgType].
    ///
    /// # Example
    /// ```rust
    /// use rosenpass_wireguard_broker::api::msgs::MsgType;
    /// let msg_type = MsgType::try_from(0x01);
    /// assert!(msg_type.is_ok());
    /// assert_eq!(msg_type.unwrap(), MsgType::SetPsk);
    /// ```
    /// # Errors
    /// Returns an [InvalidMessageTypeError] if `value` does not correspond to a valid [MsgType].
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(MsgType::SetPsk),
            _ => Err(InvalidMessageTypeError),
        }
    }
}
