//! The bulk code relating to the Rosenpass unix socket API
//!
//! # Examples
//!
#![doc = "```ignore"]
#![doc = include_str!("../../tests/api-integration-tests-api-setup.rs")]
#![doc = "```"]

mod api_handler;
mod boilerplate;

pub use api_handler::*;
pub use boilerplate::*;

pub mod cli;
pub mod config;
pub mod mio;
