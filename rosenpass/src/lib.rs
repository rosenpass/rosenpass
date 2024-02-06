#![feature(offset_of)]

pub mod app_server;
pub mod cli;
pub mod config;
pub mod hash_domains;
pub mod msgs;
pub mod protocol;

#[derive(thiserror::Error, Debug)]
pub enum RosenpassError {
    #[error("buffer size mismatch")]
    BufferSizeMismatch,
    #[error("invalid message type")]
    InvalidMessageType(u8),
}
