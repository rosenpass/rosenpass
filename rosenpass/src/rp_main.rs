//! This module holds the `main` function of the `rp` binary. Not to be confused with the
//! `rosenpass` binary.

// TODO: document the reason for the recursion limit
#![recursion_limit = "256"]

#[cfg(feature = "experiment_api")]
mod api;
mod app_server;
mod cli;
mod config;
mod error;
mod hash_domains;
mod internal;
mod msgs;
mod protocol;

use crate::cli::{CliCommand, CliGrammar};
pub use error::RosenpassError;

// TODO: remove rp_old
mod rp_old;

/// parses command line, catches errors, prints them through the logger, then exits
///
/// The bulk of the command line logic is handled inside [crate::cli::CliCommand::run].
pub fn main() {
    // DO NOT set logging here. Logging is set differently per subcommand.
    // I.e. the exchange command reads it from the command line, the exchange-config command
    // reads it from a config file, some commands just use the default.

    // run the application based on the command line arguments
    match CliCommand::parse_and_run_from_env(None, CliGrammar::Rp) {
        Ok(_) => {}
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    }
}

// - TODO: what to do with this legacy code?
//
// #[tokio::main]
// pub async fn main() -> anyhow::Result<()> {
//     ensure_janitor(async move { main_impl().await }).await
// }
