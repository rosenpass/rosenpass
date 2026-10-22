//! contains the the type [`RosenpassConfig`] and parsing + validation code
//!
//! This module is split up into the follow submodules:
//! - [`types`]: contains the [`RosenpassConfig`] type and all associated types
//! - [`parse_from_toml`]: implements the function [`RosenpassConfig::parse_from_toml`]
//! - [`validate`]: implements the function [`RosenpassConfig::validate`]
//! - [`tests`]: contains unit tests

pub mod parse_from_toml;
pub mod tests;
pub mod types;
pub mod validate;

pub use types::*;
