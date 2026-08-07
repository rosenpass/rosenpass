//! Module containing parsing and serialization from and to config files.
//!
//! Rosenpass supports reading its configuration from a TOML file. This module contains a struct
//! [`RosenpassConfig`] which holds such a configuration.
//!
//! ## TODO
//! - TODO: support `~` in <https://github.com/rosenpass/rosenpass/issues/237>
//! - TODO: provide tooling to create config file from shell <https://github.com/rosenpass/rosenpass/issues/247>

mod rosenpass_config;
pub use rosenpass_config::*;

mod rosenpass_peer;
pub use rosenpass_peer::*;

mod rosenpass_keypair;
pub use rosenpass_keypair::*;

mod protocol_version;
pub use protocol_version::*;

mod verbosity;
pub use verbosity::*;

mod wireguard;
pub use wireguard::*;

mod peer_osk_domain_seperator;
pub use peer_osk_domain_seperator::*;

mod util;
pub use util::*;

mod statics;
pub use statics::*;
