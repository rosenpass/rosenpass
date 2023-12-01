pub mod app_server;
pub mod cli;
pub mod config;
pub mod hash_domains;
pub mod msgs;
pub mod protocol;

#[derive(thiserror::Error, Debug)]
pub enum RosenpassError {
    #[error("buffer size mismatch, required {required_size} but found {actual_size}")]
    BufferSizeMismatch {
        required_size: usize,
        actual_size: usize,
    },
    #[error("invalid message type")]
    InvalidMessageType(u8),
}
