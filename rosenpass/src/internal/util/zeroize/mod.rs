//!
//! This module provides the extension trait
#![cfg_attr(feature = "expose_internal_modules", doc = "[`ZeroizedExt`],")]
#![cfg_attr(not(feature = "expose_internal_modules"), doc = "`ZeroizedExt`,")]
//! for all types implementing the
//! `zeroize::Zeroize` trait.
//! It introduces the
#![cfg_attr(
    feature = "expose_internal_modules",
    doc = "[`zeroized`](ZeroizedExt::zeroized)"
)]
#![cfg_attr(not(feature = "expose_internal_modules"), doc = "`zeroized`")]
//! method, which zeroizes a value in place and returns it, making it convenient
//! for chaining operations and ensuring sensitive data is securely erased.
//!
//! # Examples
//!
//! ```rust
//! use zeroize::Zeroize;
//! use rosenpass::internal::util::zeroize::ZeroizedExt;
//!
//! let mut value = String::from("hello");
//! value.zeroize(); // Zeroizes in place
//! assert_eq!(value, "");
//!
//! assert_eq!(String::from("hello").zeroized(), "");
//! ```

mod zeroized_ext;
pub use zeroized_ext::*;
