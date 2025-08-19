//! This library provides functionality for working with secret data and protecting it in
//! memory from illegitimate access.
//!
//! Specifically, the [alloc] module provides wrappers around the `memsec` and `memfdsec` allocators
//! from the [memsec] crate that implement the [Allocator](allocator_api2::alloc::Allocator) Trait.
//! We refer to the documentation of these modules for more details on their appropriate usage.
//!
//! The [policy] module then provides functionality for specifying which of the allocators from
//! the [alloc] module should be used.
//!
//! Once this configuration is made [Secret] can be used to store sensitive data in memory
//! allocated by the configured allocator. [Secret] is implemented such that memory is *aloways*
//! zeroized before it is released. Because allocations of the protected memory are expensive to do,
//! [Secret] is build to reuse once allocated memory. A simple use of [Secret] looks as follows:
//! # Exmaple
//! ```rust
//! use zeroize::Zeroize;
//! use rosenpass_secret_memory::{secret_policy_try_use_memfd_secrets, Secret};
//! secret_policy_try_use_memfd_secrets();
//! let mut my_secret: Secret<32> = Secret::random();
//! my_secret.zeroize();
//! ```
//!
//! # Futher functionality
//! In addition to this core functionality, this library provides some more smaller tools.
//!
//! 1. [Public] and [PublicBox] provide byte array storage for public data in a manner analogous to
//!    that of [Secret].
//! 2. The [debug] module provides functionality to easily create debug output for objects that are
//!    backed by byte arrays or slices, like for example [Secret].
//! 3. The [mod@file] module provides functionality to store [Secrets](crate::Secret)
//!    and [Public] in files such that the file's [Visibility](rosenpass_util::file::Visibility)
//!    corresponds to the confidentiality of the data.
//! 4. The [rand] module provides a simple way of generating randomness.

pub mod debug;
pub mod file;
pub mod rand;

pub mod alloc;

mod public;
pub use crate::public::Public;
pub use crate::public::PublicBox;

mod secret;
pub use crate::secret::Secret;

pub mod policy;
mod serialization;

pub use crate::policy::*;
