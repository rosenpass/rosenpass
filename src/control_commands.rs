//! Data structures representing the control messages going over the control socket
//!
//! This module uses the same de-/serialization mechanism as [crate::msgs].
//! If you want to interface with `rosenpassd`, this is where you can look up the format
//! of the messages that are accepted.

use crate::{data_lense, msgs::LenseView, RosenpassError};

data_lense! { ControlComand<C> :=
    /// [MsgType] of this message
    msg_type: 1
}

#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum CommandType {
    /// Add one peer
    AddPeer = 0x10,

    /// Remove all peers that match the given public key
    RemovePeerPk = 0x11,

    /// Remove all peers that match the given address
    RemovePeerIp = 0x12,
}

impl TryFrom<u8> for CommandType {
    type Error = RosenpassError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x10 => CommandType::AddPeer,
            0x11 => CommandType::RemovePeerPk,
            0x12 => CommandType::RemovePeerIp,
            _ => return Err(RosenpassError::InvalidMessageType(value)),
        })
    }
}
