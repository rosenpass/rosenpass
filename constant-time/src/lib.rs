#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
//! constant-time implementations of some primitives
//!
//! Rosenpass internal library providing basic constant-time operations.
//!
//! ## TODO
//! Figure out methodology to ensure that code is actually constant time, see
//! <https://github.com/rosenpass/rosenpass/issues/232>
//!
//! # Examples
//!
//! ```rust
//! use rosenpass_constant_time::{memcmp, compare};
//!
//! let a = [1, 2, 3, 4];
//! let b = [1, 2, 3, 4];
//! let c = [1, 2, 3, 5];
//!
//! // Compare for equality
//! assert!(memcmp(&a, &b));
//! assert!(!memcmp(&a, &c));
//!
//! // Compare lexicographically
//! assert_eq!(compare(&a, &c), -1); // a < c
//! assert_eq!(compare(&c, &a), 1);  // c > a
//! assert_eq!(compare(&a, &b), 0);  // a == b
//! ```
//!
//! # Security Notes
//!
//! While these functions aim to be constant-time, they may leak timing information in some cases:
//!
//! - Length mismatches between inputs are immediately detectable
//! - Execution time scales linearly with input size

mod compare;
mod increment;
mod memcmp;
mod xor;

pub use compare::compare;
pub use compare::memcmp_le;
pub use increment::increment;
pub use memcmp::memcmp;
pub use xor::xor;
