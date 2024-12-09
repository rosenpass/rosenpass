//! Data structures representing the messages going over the wire
//!
//! This module contains de-/serialization of the protocol's messages. Thats kind
//! of a lie, since no actual ser/de happens. Instead, the structures offer views
//! into mutable byte slices (`&mut [u8]`), allowing to modify the fields of an
//! always serialized instance of the data in question. This is closely related
//! to the concept of lenses in function programming; more on that here:
//! [https://sinusoid.es/misc/lager/lenses.pdf](https://sinusoid.es/misc/lager/lenses.pdf)
//! To achieve this we utilize the zerocopy library.
//!
use std::mem::size_of;
use std::u8;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use super::RosenpassError;
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::{EphemeralKem, StaticKem};
use rosenpass_ciphers::{aead, xaead, KEY_LEN};

/// Length of a session ID such as [InitHello::sidi]
pub const SESSION_ID_LEN: usize = 4;
/// Length of a biscuit ID; i.e. size of the value in [Biscuit::biscuit_no]
pub const BISCUIT_ID_LEN: usize = 12;

/// TODO: Unused, remove!
pub const WIRE_ENVELOPE_LEN: usize = 1 + 3 + 16 + 16; // TODO verify this

/// Size required to fit any message in binary form
pub const MAX_MESSAGE_LEN: usize = 2500; // TODO fix this

/// length in bytes of an unencrypted Biscuit (plain text)
pub const BISCUIT_PT_LEN: usize = size_of::<Biscuit>();

/// Length in bytes of an encrypted Biscuit (cipher text)
pub const BISCUIT_CT_LEN: usize = BISCUIT_PT_LEN + xaead::NONCE_LEN + xaead::TAG_LEN;

/// Size of the field [Envelope::mac]
pub const MAC_SIZE: usize = 16;
/// Size of the field [Envelope::cookie]
pub const COOKIE_SIZE: usize = MAC_SIZE;

/// Type of the mac field in [Envelope]
pub type MsgEnvelopeMac = [u8; MAC_SIZE];

/// Type of the cookie field in [Envelope]
pub type MsgEnvelopeCookie = [u8; COOKIE_SIZE];

/// Header and footer included in all our packages,
/// including a type field.
///
/// # Examples
///
/// ```
/// use rosenpass::msgs::{Envelope, InitHello};
/// use zerocopy::{AsBytes, FromBytes, Ref, FromZeroes};
/// use memoffset::offset_of;
///
/// // Zero-initialization
/// let mut ih = Envelope::<InitHello>::new_zeroed();
///
/// // Edit fields normally
/// ih.mac[0] = 1;
///
/// // Edit as binary
/// ih.as_bytes_mut()[offset_of!(Envelope<InitHello>, msg_type)] = 23;
/// assert_eq!(ih.msg_type, 23);;
///
/// // Conversion to bytes
/// let mut ih2 = ih.as_bytes().to_owned();
///
/// // Setting msg_type field, again
/// ih2[0] = 42;
///
/// // Zerocopy parsing
/// let ih3 = Ref::<&mut [u8], Envelope<InitHello>>::new(&mut ih2).unwrap();
/// assert_ne!(ih.as_bytes(), ih3.as_bytes());
/// assert_eq!(ih3.msg_type, 42);
/// ```
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone)]
pub struct Envelope<M: AsBytes + FromBytes> {
    /// [MsgType] of this message
    pub msg_type: u8,
    /// Reserved for future use
    pub reserved: [u8; 3],
    /// The actual Paylod
    pub payload: M,
    /// Message Authentication Code (mac) over all bytes until (exclusive)
    /// `mac` itself
    pub mac: MsgEnvelopeMac,
    /// Currently unused, TODO: do something with this
    pub cookie: MsgEnvelopeCookie,
}

/// This is the first message sent by the initiator to the responder
/// during the execution of the Rosenpass protocol.
///
/// When transmitted on the wire, this type will generally be wrapped into [Envelope].
///
/// # Examples
///
/// Check out the code of [crate::protocol::CryptoServer::handle_initiation] (generation on
/// iniatiator side) and [crate::protocol::CryptoServer::handle_init_hello] (processing on
/// responder side) to understand how this is used.
///
/// [Envelope] contains some extra examples on how to use structures from the [::zerocopy] crate.
///
/// ```
/// use rosenpass::msgs::{Envelope, InitHello};
/// use zerocopy::{AsBytes, FromBytes, Ref, FromZeroes};
/// use memoffset::span_of;
///
/// // Zero initialization
/// let mut ih = Envelope::<InitHello>::new_zeroed();
///
/// // Conversion to byte representation
/// let ih = ih.as_bytes_mut();
///
/// // Set value on byte representation
/// ih[span_of!(Envelope<InitHello>, payload)][span_of!(InitHello, sidi)]
///     .copy_from_slice(&[1,2,3,4]);
///
/// // Conversion from bytes
/// let ih = Ref::<&mut [u8], Envelope<InitHello>>::new(ih).unwrap();
///
/// // Check that write above on byte representation was effective
/// assert_eq!(ih.payload.sidi, [1,2,3,4]);
/// ```
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

/// This is the second message sent by the responder to the initiator
/// during the execution of the Rosenpass protocol in response to [InitHello].
///
/// When transmitted on the wire, this type will generally be wrapped into [Envelope].
///
/// # Examples
///
/// Check out the code of [crate::protocol::CryptoServer::handle_init_hello] (generation on
/// responder side) and [crate::protocol::CryptoServer::handle_resp_hello] (processing on
/// initiator side) to understand how this is used.
///
/// [Envelope] contains some extra examples on how to use structures from the [::zerocopy] crate.
///
/// ```
/// use rosenpass::msgs::{Envelope, RespHello};
/// use zerocopy::{AsBytes, FromBytes, Ref, FromZeroes};
/// use memoffset::span_of;
///
/// // Zero initialization
/// let mut ih = Envelope::<RespHello>::new_zeroed();
///
/// // Conversion to byte representation
/// let ih = ih.as_bytes_mut();
///
/// // Set value on byte representation
/// ih[span_of!(Envelope<RespHello>, payload)][span_of!(RespHello, sidi)]
///     .copy_from_slice(&[1,2,3,4]);
///
/// // Conversion from bytes
/// let ih = Ref::<&mut [u8], Envelope<RespHello>>::new(ih).unwrap();
///
/// // Check that write above on byte representation was effective
/// assert_eq!(ih.payload.sidi, [1,2,3,4]);
/// ```
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

/// This is the third message sent by the initiator to the responder
/// during the execution of the Rosenpass protocol in response to [RespHello].
///
/// When transmitted on the wire, this type will generally be wrapped into [Envelope].
///
/// # Examples
///
/// Check out the code of [crate::protocol::CryptoServer::handle_resp_hello] (generation on
/// initiator side) and [crate::protocol::CryptoServer::handle_init_conf] (processing on
/// responder side) to understand how this is used.
///
/// [Envelope] contains some extra examples on how to use structures from the [::zerocopy] crate.
///
/// ```
/// use rosenpass::msgs::{Envelope, InitConf};
/// use zerocopy::{AsBytes, FromBytes, Ref, FromZeroes};
/// use memoffset::span_of;
///
/// // Zero initialization
/// let mut ih = Envelope::<InitConf>::new_zeroed();
///
/// // Conversion to byte representation
/// let ih = ih.as_bytes_mut();
///
/// // Set value on byte representation
/// ih[span_of!(Envelope<InitConf>, payload)][span_of!(InitConf, sidi)]
///     .copy_from_slice(&[1,2,3,4]);
///
/// // Conversion from bytes
/// let ih = Ref::<&mut [u8], Envelope<InitConf>>::new(ih).unwrap();
///
/// // Check that write above on byte representation was effective
/// assert_eq!(ih.payload.sidi, [1,2,3,4]);
/// ```
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Debug)]
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

/// This is the fourth message sent by the initiator to the responder
/// during the execution of the Rosenpass protocol in response to [RespHello].
///
/// When transmitted on the wire, this type will generally be wrapped into [Envelope].
///
/// This message does not serve a cryptographic purpose; it just tells the initiator
/// to stop package retransmission.
///
/// This message should really be called `RespConf`, but when we wrote the protocol,
/// we initially designed the protocol we still though Rosenpass itself should do
/// payload transmission at some point so `EmptyData` could have served as a more generic
/// mechanism.
///
/// We might add payload transmission in the future again, but we will treat
/// it as a protocol extension if we do.
///
/// # Examples
///
/// Check out the code of [crate::protocol::CryptoServer::handle_init_conf] (generation on
/// responder side) and [crate::protocol::CryptoServer::handle_resp_conf] (processing on
/// initiator side) to understand how this is used.
///
/// [Envelope] contains some extra examples on how to use structures from the [::zerocopy] crate.
///
/// ```
/// use rosenpass::msgs::{Envelope, EmptyData};
/// use zerocopy::{AsBytes, FromBytes, Ref, FromZeroes};
/// use memoffset::span_of;
///
/// // Zero initialization
/// let mut ih = Envelope::<EmptyData>::new_zeroed();
///
/// // Conversion to byte representation
/// let ih = ih.as_bytes_mut();
///
/// // Set value on byte representation
/// ih[span_of!(Envelope<EmptyData>, payload)][span_of!(EmptyData, sid)]
///     .copy_from_slice(&[1,2,3,4]);
///
/// // Conversion from bytes
/// let ih = Ref::<&mut [u8], Envelope<EmptyData>>::new(ih).unwrap();
///
/// // Check that write above on byte representation was effective
/// assert_eq!(ih.payload.sid, [1,2,3,4]);
/// ```
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes, Clone, Copy)]
pub struct EmptyData {
    /// Copied from RespHello
    pub sid: [u8; 4],
    /// Nonce
    pub ctr: [u8; 8],
    /// Empty encrypted message (just an auth tag)
    pub auth: [u8; aead::TAG_LEN],
}

/// Cookie encrypted and sent to the initiator by the responder in [RespHello]
/// and returned by the initiator in [InitConf].
///
/// The encryption key is randomly chosen by the responder and frequently regenerated.
/// Using this biscuit value in the protocol allows us to make sure that the responder
/// is mostly stateless until full initiator authentication is achieved, which is needed
/// to prevent denial of service attacks. See the [whitepaper](https://rosenpass.eu/whitepaper.pdf)
/// ([/papers/whitepaper.md] in this repository).
///
/// # Examples
///
/// To understand how the biscuit is used, it is best to read
/// the code of [crate::protocol::HandshakeState::store_biscuit] and
/// [crate::protocol::HandshakeState::load_biscuit]
///
/// [Envelope] and [InitHello] contain some extra examples on how to use structures from the [::zerocopy] crate.
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

/// Specialized message for use in the cookie mechanism.
///
/// See the [whitepaper](https://rosenpass.eu/whitepaper.pdf) ([/papers/whitepaper.md] in this repository) for details.
///
/// Generally used together with [CookieReply] which brings this up to the size
/// of [InitHello] to avoid amplification Denial of Service attacks.
///
/// # Examples
///
/// To understand how the biscuit is used, it is best to read
/// the code of [crate::protocol::CryptoServer::handle_cookie_reply] and
/// [crate::protocol::CryptoServer::handle_msg_under_load].
///
/// [Envelope] and [InitHello] contain some extra examples on how to use structures from the [::zerocopy] crate.
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct CookieReplyInner {
    /// [MsgType] of this message
    pub msg_type: u8,
    /// Reserved for future use
    pub reserved: [u8; 3],
    /// Session ID of the sender (initiator)
    pub sid: [u8; 4],
    /// Encrypted cookie with authenticated initiator `mac`
    pub cookie_encrypted: [u8; xaead::NONCE_LEN + COOKIE_SIZE + xaead::TAG_LEN],
}

/// Specialized message for use in the cookie mechanism.
///
/// This just brings [CookieReplyInner] up to the size
/// of [InitHello] to avoid amplification Denial of Service attacks.
///
/// See the [whitepaper](https://rosenpass.eu/whitepaper.pdf) ([/papers/whitepaper.md] in this repository) for details.
///
/// # Examples
///
/// To understand how the biscuit is used, it is best to read
/// the code of [crate::protocol::CryptoServer::handle_cookie_reply] and
/// [crate::protocol::CryptoServer::handle_msg_under_load].
///
/// [Envelope] and [InitHello] contain some extra examples on how to use structures from the [::zerocopy] crate.
#[repr(packed)]
#[derive(AsBytes, FromBytes, FromZeroes)]
pub struct CookieReply {
    pub inner: CookieReplyInner,
    pub padding: [u8; size_of::<Envelope<InitHello>>() - size_of::<CookieReplyInner>()],
}

/// Recognized message types
///
/// # Examples
///
/// ```
/// use rosenpass::msgs::MsgType;
/// use rosenpass::msgs::MsgType as M;
///
/// let values = [M::InitHello, M::RespHello, M::InitConf, M::EmptyData, M::CookieReply];
/// let values_u8 = values.map(|v| -> u8 { v.into() });
///
/// // Can be converted to and from u8 using [::std::convert::Into] or [::std::convert::From]
/// for v in values.iter().copied() {
///     let v_u8 : u8 = v.into();
///     let v2 : MsgType = v_u8.try_into()?;
///     assert_eq!(v, v2);
/// }
///
/// // Converting an unsupported type produces an error
/// let invalid_values = (u8::MIN..=u8::MAX)
///     .filter(|v| !values_u8.contains(v));
/// for v in invalid_values {
///     let res : Result<MsgType, _> = v.try_into();
///     assert!(res.is_err());
/// }
///
/// Ok::<(), anyhow::Error>(())
/// ```
#[repr(u8)]
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Copy)]
pub enum MsgType {
    /// MsgType for [InitHello]
    InitHello = 0x81,
    /// MsgType for [RespHello]
    RespHello = 0x82,
    /// MsgType for [InitConf]
    InitConf = 0x83,
    /// MsgType for [EmptyData]
    EmptyData = 0x84,
    /// MsgType for [CookieReply]
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
            0x86 => MsgType::CookieReply,
            _ => return Err(RosenpassError::InvalidMessageType(value)),
        })
    }
}

impl From<MsgType> for u8 {
    fn from(val: MsgType) -> Self {
        val as u8
    }
}

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
