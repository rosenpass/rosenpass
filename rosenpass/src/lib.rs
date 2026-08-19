// #![warn(missing_docs)]
// #![warn(clippy::missing_docs_in_private_items)]
#![recursion_limit = "256"]

//! This is the central rosenpass crate implementing the rosenpass protocol.
//!
//! It contains the following modules:
//! - [`crate::app_server`] contains the business logic of rosenpass, handling networking
//! - [`crate::cli`] contains the cli parsing logic and contains quite a bit of startup logic; the
//!   main function quickly hands over to [`crate::cli::CliArgs::run`] which contains quite a bit
//!   of our startup logic
//! - [`crate::config`] has the code to parse and generate configuration files
//! - [`crate::hash_domains`] lists the different hash function domains used in the Rosenpass
//!   protocol
//! - [`crate::msgs`] provides declarations of the Rosenpass protocol network messages and facilities
//!   to parse those messages through the [`zerocopy`] crate
//! - [`crate::protocol`] this is where the bulk of our code lives; this module contains the actual
//!   cryptographic protocol logic
#![cfg_attr(
    feature = "experiment_api",
    doc = r#"
 - [`crate::api`] implements the Rosenpass unix socket API, if feature `experiment_api` is enabled
"#
)]
#![cfg_attr(
    feature = "expose_internal_modules",
    doc = r#"
 - [`crate::internal`] contains various internal modules which are only exposed if feature
   `expose_internal_module` is enabled (see module description for explanation)
"#
)]
pub mod app_server;
pub mod cli;
pub mod config;
pub mod hash_domains;
pub mod msgs;
pub mod protocol;

#[cfg(feature = "experiment_api")]
pub mod api;

#[cfg(not(feature = "expose_internal_modules"))]
pub(crate) mod internal;
#[cfg(feature = "expose_internal_modules")]
pub mod internal;

mod error;
pub use error::RosenpassError;
