//! This is the central rosenpass crate implementing the rosenpass protocol.
//!
//! - [crate::app_server] contains the business logic of rosenpass, handling networking
//! - [crate::cli] contains the cli parsing logic and contains quite a bit of startup logic; the
//!   main function quickly hands over to [crate::cli::CliArgs::run] which contains quite a bit
//!   of our startup logic
//! - [crate::config] has the code to parse and generate configuration files
//! - [crate::hash_domains] lists the different hash function domains used in the Rosenpass
//!   protocol
//! - [crate::msgs] provides declarations of the Rosenpass protocol network messages and facilities
//!   to parse those messages through the [::zerocopy] crate
//! - [crate::protocol] this is where the bulk of our code lives; this module contains the actual
//!   cryptographic protocol logic
//! - crate::api implements the Rosenpass unix socket API, if feature "experiment_api" is active

#[cfg(feature = "experiment_api")]
pub mod api;
pub mod app_server;
pub mod cli;
pub mod config;
pub mod hash_domains;
pub mod msgs;
pub mod protocol;

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
