use zerocopy::{ByteSliceMut, Ref};

use rosenpass_util::zerocopy::RefMaker;

use super::RawMsgType;

/// Trait implemented by all the Rosenpass API message types.
///
/// Implemented by the message as including the message envelope; e.g.
/// [crate::api::PingRequest] but not by [crate::api::PingRequestPayload].
pub trait Message {
    /// The payload this API message contains. E.g. this is [crate::api::PingRequestPayload] for [[crate::api::PingRequest].
    type Payload;
    /// Either [crate::api::RequestMsgType] or [crate::api::ResponseMsgType]
    type MessageClass: Into<RawMsgType>;
    /// The specific message type in the [Self::MessageClass].
    /// E.g. this is [crate::api::RequestMsgType::Ping] for [crate::api::PingRequest]
    const MESSAGE_TYPE: Self::MessageClass;

    /// Wraps the payload into the envelope
    ///
    /// # Examples
    ///
    /// See [crate::api::PingRequest::from_payload]
    fn from_payload(payload: Self::Payload) -> Self;
    /// Initialize the message;
    /// just sets the message type [crate::api::Envelope::msg_type].
    ///
    /// # Examples
    ///
    /// See [crate::api::PingRequest::init]
    fn init(&mut self);
    /// Initialize the message from a raw buffer: Zeroize the buffer and then call [Self::init].
    ///
    /// # Examples
    ///
    /// See [crate::api::PingRequest::setup]
    fn setup<B: ByteSliceMut>(buf: B) -> anyhow::Result<Ref<B, Self>>;
}

/// Additional convenience functions for working with [rosenpass_util::zerocopy::RefMaker]
pub trait ZerocopyResponseMakerSetupMessageExt<B, T> {
    fn setup_msg(self) -> anyhow::Result<Ref<B, T>>;
}

impl<B, T> ZerocopyResponseMakerSetupMessageExt<B, T> for RefMaker<B, T>
where
    B: ByteSliceMut,
    T: Message,
{
    /// Initialize the message using [Message::setup].
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::api::{
    ///     PingRequest, ZerocopyResponseMakerSetupMessageExt, PING_REQUEST,
    /// };
    /// use rosenpass_util::zerocopy::RefMaker;
    /// use std::mem::size_of;
    ///
    /// let mut buf = [0u8; { size_of::<PingRequest>() }];
    ///
    /// let rm = RefMaker::<&mut [u8], PingRequest>::new(&mut buf);
    /// let msg: zerocopy::Ref<_, PingRequest> = rm.setup_msg()?;
    ///
    /// let t = msg.msg_type; // Deal with unaligned read
    /// assert_eq!(t, PING_REQUEST);
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    fn setup_msg(self) -> anyhow::Result<Ref<B, T>> {
        T::setup(self.into_buf())
    }
}
