//! Shared-memory byte streams and Unix-socket upgrade preparation.

pub mod mio;

pub use mio::{MioFdStream, ShmStreamError};
