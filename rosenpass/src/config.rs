//! Configuration readable from a config file.
//!
//! Rosenpass supports reading its configuration from a TOML file. This module contains a struct
//! [`Rosenpass`] which holds such a configuration.
//!
//! ## TODO
//! - TODO: support `~` in <https://github.com/rosenpass/rosenpass/issues/237>
//! - TODO: provide tooling to create config file from shell <https://github.com/rosenpass/rosenpass/issues/247>

pub mod peer_osk_domain_seperator;
pub mod rosenpass_keypair;
pub mod util;
pub mod verbosity;
pub mod wireguard;
pub mod rosenpass_peer;
pub mod protocol_version;
pub mod statics;
mod rosenpass_config;
pub use rosenpass_config::*;