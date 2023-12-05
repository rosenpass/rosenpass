//! Data structures representing the messages going over the wire
//!
//! This module contains de-/serialization of the protocol's messages. Thats kind
//! of a lie, since no actual ser/de happens. Instead, the structures offer views
//! into mutable byte slices (`&mut [u8]`), allowing to modify the fields of an
//! always serialized instance of the data in question. This is closely related
//! to the concept of lenses in function programming; more on that here:
//! [https://sinusoid.es/misc/lager/lenses.pdf](https://sinusoid.es/misc/lager/lenses.pdf)
//!
//! # Example
//!
//! The following example uses the [`lense` macro](rosenpass_lenses::lense) to create a lense that
//! might be useful when dealing with UDP headers.
//!
//! ```
//! use rosenpass_lenses::{lense, LenseView};
//! use rosenpass::RosenpassError;
//! # fn main() -> Result<(), RosenpassError> {
//!
//! lense! {UdpDatagramHeader :=
//!     source_port: 2,
//!     dest_port: 2,
//!     length: 2,
//!     checksum: 2
//! }
//!
//! let mut buf = [0u8; 8];
//!
//! // read-only lense, no check of size:
//! let lense = UdpDatagramHeader(&buf);
//! assert_eq!(lense.checksum(), &[0, 0]);
//!
//! // mutable lense, runtime check of size
//! let mut lense = buf.as_mut().udp_datagram_header()?;
//! lense.source_port_mut().copy_from_slice(&53u16.to_be_bytes()); // some DNS, anyone?
//!
//! // the original buffer is still available
//! assert_eq!(buf, [0, 53, 0, 0, 0, 0, 0, 0]);
//!
//! // read-only lense, runtime check of size
//! let lense = buf.as_ref().udp_datagram_header()?;
//! assert_eq!(lense.source_port(), &[0, 53]);
//! # Ok(())
//! # }
//! ```

use super::RosenpassError;
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::{EphemeralKem, StaticKem};
use rosenpass_ciphers::{aead, xaead, KEY_LEN};
use rosenpass_lenses::{lense, LenseView};
pub const MAC_SIZE: usize = 16;
pub const COOKIE_SIZE: usize = 16;

// Macro magic ////////////////////////////////////////////////////////////////

lense! { Envelope<M> :=
    /// [MsgType] of this message
    msg_type: 1,
    /// Reserved for future use
    reserved: 3,
    /// The actual Paylod
    payload: M::LEN,
    /// Message Authentication Code (mac) over all bytes until (exclusive)
    /// `mac` itself
    mac: MAC_SIZE,
    /// Cookie value
    cookie: COOKIE_SIZE
}

lense! { InitHello :=
    /// Randomly generated connection id
    sidi: 4,
    /// Kyber 512 Ephemeral Public Key
    epki: EphemeralKem::PK_LEN,
    /// Classic McEliece Ciphertext
    sctr: StaticKem::CT_LEN,
    /// Encryped: 16 byte hash of McEliece initiator static key
    pidic: aead::TAG_LEN + 32,
    /// Encrypted TAI64N Time Stamp (against replay attacks)
    auth: aead::TAG_LEN
}

lense! { RespHello :=
    /// Randomly generated connection id
    sidr: 4,
    /// Copied from InitHello
    sidi: 4,
    /// Kyber 512 Ephemeral Ciphertext
    ecti: EphemeralKem::CT_LEN,
    /// Classic McEliece Ciphertext
    scti: StaticKem::CT_LEN,
    /// Empty encrypted message (just an auth tag)
    auth: aead::TAG_LEN,
    /// Responders handshake state in encrypted form
    biscuit: BISCUIT_CT_LEN
}

lense! { InitConf :=
    /// Copied from InitHello
    sidi: 4,
    /// Copied from RespHello
    sidr: 4,
    /// Responders handshake state in encrypted form
    biscuit: BISCUIT_CT_LEN,
    /// Empty encrypted message (just an auth tag)
    auth: aead::TAG_LEN
}

lense! { EmptyData :=
    /// Copied from RespHello
    sid: 4,
    /// Nonce
    ctr: 8,
    /// Empty encrypted message (just an auth tag)
    auth: aead::TAG_LEN
}

lense! { Biscuit :=
    /// H(spki) – Ident ifies the initiator
    pidi: KEY_LEN,
    /// The biscuit number (replay protection)
    biscuit_no: 12,
    /// Chaining key
    ck: KEY_LEN
}

lense! { DataMsg :=
    dummy: 4
}

lense! { CookieReply :=
    sid: 4,
    nonce: xaead::NONCE_LEN,
    cookie_encrypted: MAC_SIZE + xaead::TAG_LEN
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
pub const BISCUIT_PT_LEN: usize = Biscuit::<()>::LEN;

/// Length in bytes of an encrypted Biscuit (cipher text)
pub const BISCUIT_CT_LEN: usize = BISCUIT_PT_LEN + xaead::NONCE_LEN + xaead::TAG_LEN;

#[cfg(test)]
mod test_constants {
    use crate::msgs::{BISCUIT_CT_LEN, BISCUIT_PT_LEN};
    use rosenpass_ciphers::{xaead, KEY_LEN};
    use serial_test::parallel;

    #[test]
    #[parallel]
    fn sodium_keysize() {
        assert_eq!(KEY_LEN, 32);
    }

    #[test]
    #[parallel]
    fn biscuit_pt_len() {
        assert_eq!(BISCUIT_PT_LEN, 2 * KEY_LEN + 12);
    }

    #[test]
    #[parallel]
    fn biscuit_ct_len() {
        assert_eq!(
            BISCUIT_CT_LEN,
            BISCUIT_PT_LEN + xaead::NONCE_LEN + xaead::TAG_LEN
        );
    }
}
