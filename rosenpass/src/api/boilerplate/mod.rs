//! Boring, repetitive code related to message parsing for the API.
//!
//! Most of this should be automatically generated though some derive macro at some point.

mod byte_slice_ext;
mod message_trait;
mod message_type;
mod payload;
mod request_ref;
mod request_response;
mod response_ref;
mod server;

pub use byte_slice_ext::*;
pub use message_trait::*;
pub use message_type::*;
pub use payload::*;
pub use request_ref::*;
pub use request_response::*;
pub use response_ref::*;
pub use server::*;
