/// Error types used in diverse places across Rosenpass
#[derive(thiserror::Error, Debug)]
pub enum RosenpassError {
    /// Usually indicates that parsing a struct through the
    /// [::zerocopy] crate failed
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
    /// Mostly raised by the `TryFrom<u8>` implementation for [crate::msgs::MsgType]
    /// to indicate that a message type is not defined
    #[error("invalid message type")]
    InvalidMessageType(
        /// The message type that could not be parsed
        u8,
    ),
    /// Raised by the `TryFrom<RawMsgType>` (crate::api::RawMsgType) implementation for crate::api::RequestMsgType
    /// and crate::api::RequestMsgType to indicate that a message type is not defined
    #[error("invalid API message type")]
    InvalidApiMessageType(
        /// The message type that could not be parsed
        u128,
    ),
}
