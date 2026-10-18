//! # Rosenpass secure memory library
//!
//! This library provides functionality for working with secret data and protecting it in
//! memory from illegitimate access.
//!
//! Specifically, the [alloc] module provides wrappers around the `memsec` and `memfdsec` allocators
//! from the [memsec] crate that implement the [Allocator](allocator_api2::alloc::Allocator) Trait.
//! We refer to the documentation of these modules for more details on their appropriate usage.
//!
//! The allocator automatically uses memfd-secret when available, falling back to the memsec
//! malloc backend otherwise. No initialization is required before using [Secret].
//! [Secret] is implemented such that memory is *always*
//! zeroized before it is released. Because allocations of the protected memory are expensive to do,
//! [Secret] is build to reuse once allocated memory. A simple use of [Secret] looks as follows:
//! ## Example
#![cfg_attr(feature = "expose_internal_modules", doc = "```rust")]
#![cfg_attr(not(feature = "expose_internal_modules"), doc = "```rust,ignore")]
//! use zeroize::Zeroize;
//! use rosenpass::internal::secret_memory::Secret;
//! let mut my_secret: Secret<32> = Secret::random();
//! my_secret.zeroize();
//! ```
//!
//! ## Futher functionality
//! In addition to this core functionality, this library provides some more smaller tools.
//!
//! 1. [Public] and [PublicBox] provide byte array storage for public data in a manner analogous to
//!    that of [`Secret`].
//! 2. The [debug] module provides functionality to easily create debug output for objects that are
//!    backed by byte arrays or slices, like for example [`Secret`].
//! 3. The [mod@file] module provides functionality to store [`Secrets`](Secret)
//!    and [Public] in files such that the file's [Visibility](crate::internal::util::file::Visibility)
//!    corresponds to the confidentiality of the data.
//! 4. The [rand] module provides a simple way of generating randomness.
//!
//! This is an internal library; no guarantee is made about its API at this point in time.

pub mod debug;
pub mod file;
pub mod rand;

pub mod alloc;

mod public;
pub use public::Public;
pub use public::PublicBox;

mod secret;
pub use secret::Secret;

mod serialization;
