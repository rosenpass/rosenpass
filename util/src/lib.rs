#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
#![recursion_limit = "256"]

//! Core utility functions and types used across the codebase.

/// Base64 encoding and decoding functionality.
pub mod b64;
/// Build-time utilities and macros.
pub mod build;
/// Control flow abstractions and utilities.
pub mod controlflow;
/// File descriptor utilities.
pub mod fd;
/// File system operations and handling.
pub mod file;
/// Functional programming utilities.
pub mod functional;
/// Input/output operations.
pub mod io;
/// Length prefix encoding schemes implementation.
pub mod length_prefix_encoding;
/// Memory manipulation and allocation utilities.
pub mod mem;
/// MIO integration utilities.
pub mod mio;
/// Extended Option type functionality.
pub mod option;
/// Extended Result type functionality.
pub mod result;
/// Time and duration utilities.
pub mod time;
/// Type-level numbers and arithmetic.
pub mod typenum;
/// Zero-copy serialization utilities.
pub mod zerocopy;
/// Memory wiping utilities.
pub mod zeroize;
