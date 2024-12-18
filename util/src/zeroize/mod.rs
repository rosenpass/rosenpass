//!
//! This module provides an extension trait,
//! [`ZeroizedExt`](crate::zeroize::ZeroizedExt), for all types implementing the
//! `zeroize::Zeroize` trait.
//! It introduces the [`zeroized`](crate::zeroize::ZeroizedExt::zeroized)
//! method, which zeroizes a value in place and returns it, making it convenient
//! for chaining operations and ensuring sensitive data is securely erased.
//!
//! # Examples
//!
//! ```rust
//! use zeroize::Zeroize;
//! use rosenpass_util::zeroize::ZeroizedExt;
//!
//! let mut value = String::from("hello");
//! value.zeroize(); // Zeroizes in place
//! assert_eq!(value, "");
//!
//! assert_eq!(String::from("hello").zeroized(), "");
//! ```

mod zeroized_ext;
pub use zeroized_ext::*;
