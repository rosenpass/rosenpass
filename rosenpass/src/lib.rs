#[cfg(feature = "experiment_api")]
pub mod api;
pub mod app_server;
pub mod broker;
pub mod cli;
pub mod cmd;
pub mod config;
pub mod event_loop;
pub mod hash_domains;
pub mod msgs;
pub mod protocol;

#[derive(thiserror::Error, Debug)]
pub enum RosenpassError {
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
    #[error("invalid message type")]
    InvalidMessageType(u8),
    #[error("invalid API message type")]
    InvalidApiMessageType(u128),
    #[error("could not parse API message")]
    InvalidApiMessage,
}
