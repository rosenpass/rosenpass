//! Data structures representing the messages going over the wire
//!
//! This module contains de-/serialization of the protocol's messages. Thats kind
//! of a lie, since no actual ser/de happens. Instead, the structures offer views
//! into mutable byte slices (`&mut [u8]`), allowing to modify the fields of an
//! always serialized instance of the data in question. This is closely related
//! to the concept of lenses in function programming; more on that here:
//! [https://sinusoid.es/misc/lager/lenses.pdf](https://sinusoid.es/misc/lager/lenses.pdf)
//! To achieve this we utilize the zerocopy library.

use super::RosenpassError;
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::{EphemeralKem, StaticKem};
use rosenpass_ciphers::{aead, xaead, KEY_LEN};
use std::mem::size_of;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct Envelope<M: AsBytes + FromBytes> {
    /// [MsgType] of this message
    pub msg_type: u8,
    /// Reserved for future use
    pub reserved: [u8; 3],
    /// The actual Paylod
    pub payload: M,
    /// Message Authentication Code (mac) over all bytes until (exclusive)
    /// `mac` itself
    pub mac: [u8; 16],
    /// Currently unused, TODO: do something with this
    pub cookie: [u8; 16],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct InitHello {
    /// Randomly generated connection id
    pub sidi: [u8; 4],
    /// Kyber 512 Ephemeral Public Key
    pub epki: [u8; EphemeralKem::PK_LEN],
    /// Classic McEliece Ciphertext
    pub sctr: [u8; StaticKem::CT_LEN],
    /// Encryped: 16 byte hash of McEliece initiator static key
    pub pidic: [u8; aead::TAG_LEN + 32],
    /// Encrypted TAI64N Time Stamp (against replay attacks)
    pub auth: [u8; aead::TAG_LEN],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct RespHello {
    /// Randomly generated connection id
    pub sidr: [u8; 4],
    /// Copied from InitHello
    pub sidi: [u8; 4],
    /// Kyber 512 Ephemeral Ciphertext
    pub ecti: [u8; EphemeralKem::CT_LEN],
    /// Classic McEliece Ciphertext
    pub scti: [u8; StaticKem::CT_LEN],
    /// Empty encrypted message (just an auth tag)
    pub auth: [u8; aead::TAG_LEN],
    /// Responders handshake state in encrypted form
    pub biscuit: [u8; BISCUIT_CT_LEN],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct InitConf {
    /// Copied from InitHello
    pub sidi: [u8; 4],
    /// Copied from RespHello
    pub sidr: [u8; 4],
    /// Responders handshake state in encrypted form
    pub biscuit: [u8; BISCUIT_CT_LEN],
    /// Empty encrypted message (just an auth tag)
    pub auth: [u8; aead::TAG_LEN],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct EmptyData {
    /// Copied from RespHello
    pub sid: [u8; 4],
    /// Nonce
    pub ctr: [u8; 8],
    /// Empty encrypted message (just an auth tag)
    pub auth: [u8; aead::TAG_LEN],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct Biscuit {
    /// H(spki) – Ident ifies the initiator
    pub pidi: [u8; KEY_LEN],
    /// The biscuit number (replay protection)
    pub biscuit_no: [u8; 12],
    /// Chaining key
    pub ck: [u8; KEY_LEN],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct DataMsg {
    pub dummy: [u8; 4],
}

#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct CookieReply {
    pub dummy: [u8; 4],
}

// Traits /////////////////////////////////////////////////////////////////////

pub trait WireMsg: std::fmt::Debug {
    const MSG_TYPE: MsgType;
    const MSG_TYPE_U8: u8 = Self::MSG_TYPE as u8;
    const BYTES: usize;
}

// Constants //////////////////////////////////////////////////////////////////

pub const SESSION_ID_LEN: usize = 4;
pub const BISCUIT_ID_LEN: usize = 12;

pub const WIRE_ENVELOPE_LEN: usize = 1 + 3 + 16 + 16; // TODO verify this

/// Size required to fit any message in binary form
pub const MAX_MESSAGE_LEN: usize = 2500; // TODO fix this

/// Recognized message types
#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum MsgType {
    InitHello = 0x81,
    RespHello = 0x82,
    InitConf = 0x83,
    EmptyData = 0x84,
    DataMsg = 0x85,
    CookieReply = 0x86,
}

impl TryFrom<u8> for MsgType {
    type Error = RosenpassError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Ok(match value {
            0x81 => MsgType::InitHello,
            0x82 => MsgType::RespHello,
            0x83 => MsgType::InitConf,
            0x84 => MsgType::EmptyData,
            0x85 => MsgType::DataMsg,
            0x86 => MsgType::CookieReply,
            _ => return Err(RosenpassError::InvalidMessageType(value)),
        })
    }
}

/// length in bytes of an unencrypted Biscuit (plain text)
pub const BISCUIT_PT_LEN: usize = size_of::<Biscuit>();

/// Length in bytes of an encrypted Biscuit (cipher text)
pub const BISCUIT_CT_LEN: usize = BISCUIT_PT_LEN + xaead::NONCE_LEN + xaead::TAG_LEN;

#[cfg(test)]
mod test_constants {
    use crate::msgs::{BISCUIT_CT_LEN, BISCUIT_PT_LEN};
    use rosenpass_ciphers::{xaead, KEY_LEN};

    #[test]
    fn sodium_keysize() {
        assert_eq!(KEY_LEN, 32);
    }

    #[test]
    fn biscuit_pt_len() {
        assert_eq!(BISCUIT_PT_LEN, 2 * KEY_LEN + 12);
    }

    #[test]
    fn biscuit_ct_len() {
        assert_eq!(
            BISCUIT_CT_LEN,
            BISCUIT_PT_LEN + xaead::NONCE_LEN + xaead::TAG_LEN
        );
    }
}
