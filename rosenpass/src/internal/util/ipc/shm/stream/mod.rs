//! Shared-memory byte streams and Unix-socket upgrade preparation.

pub mod mio;
pub mod sync;

pub use mio::{MioFdStream, ShmStreamError};
pub use sync::SyncFdStream;
