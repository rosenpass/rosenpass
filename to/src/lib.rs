#![warn(missing_docs)]
#![recursion_limit = "256"]
#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]

#[cfg(doctest)]
doc_comment::doctest!("../README.md");

// Core implementation
mod to;
pub use crate::to::{
    beside::Beside, condense::CondenseBeside, dst_coercion::DstCoercion, to_function::to,
    to_trait::To, with_destination::with_destination,
    to_trait::ToLifetime,
};

// Example use cases
pub mod ops;
