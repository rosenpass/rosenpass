#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
//! constant-time implementations of some primitives
//!
//! Rosenpass internal library providing basic constant-time operations.
//!
//! ## TODO
//! Figure out methodology to ensure that code is actually constant time, see
//! <https://github.com/rosenpass/rosenpass/issues/232>

mod compare;
mod increment;
mod memcmp;
mod xor;

pub use compare::compare;
pub use increment::increment;
pub use memcmp::memcmp;
pub use xor::xor;
