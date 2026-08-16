//! This module implements the binary WireGuard broker protocol in the form of the [client::BrokerClient]
//! and the [server::BrokerServer].
//!
//! Specifically, The protocol enables the client to tell the server to set a pre-shared key for a
//! wireguard interface.

pub mod client;
pub mod config;
pub mod msgs;
pub mod server;
