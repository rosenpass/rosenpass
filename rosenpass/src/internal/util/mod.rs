#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]

//! Core utility functions and types used across the codebase.

/// Base64 encoding and decoding functionality.
pub mod b64;
/// Build-time utilities and macros.
pub mod build;
/// Control flow abstractions and utilities.
pub mod controlflow;
/// File system operations and handling.
pub mod file;
pub mod fmt;
/// Functional programming utilities.
pub mod functional;
/// Input/output operations.
pub mod io;
/// Length prefix encoding schemes implementation.
pub mod length_prefix_encoding;
/// Memory manipulation and allocation utilities.
pub mod mem;
/// [MIO (Metal I/O)](https://docs.rs/crate/mio/) integration utilities.
pub mod mio;
/// Extended Option type functionality.
pub mod option;
/// Extended Result type functionality.
pub mod result;
pub mod rustix;
/// Time and duration utilities.
pub mod time;
#[cfg(feature = "tokio")]
pub mod tokio;
/// Trace benchmarking utilities
#[cfg(feature = "trace_bench")]
pub mod trace_bench;
/// Type-level numbers and arithmetic.
pub mod typenum;
/// Zero-copy serialization utilities.
pub mod zerocopy;
/// Memory wiping utilities.
pub mod zeroize;

#[allow(unused_imports)]
pub use controlflow::break_if;
#[allow(unused_imports)]
pub use controlflow::continue_if;
#[allow(unused_imports)]
pub use controlflow::repeat;
pub use controlflow::return_if;
#[allow(unused_imports)]
pub use controlflow::return_unless;
pub use mem::cat;
pub use result::attempt;
#[allow(unused_imports)]
pub use typenum::typenum2const;
