//! Contains the code used to parse command line parameters for rosenpass.
//!
//! [CliCommand::run] is called by the rosenpass main function and contains the
//! bulk of our boostrapping code while the main function just sets up the basic environment

use crate::app_server::AppServerTest;
use std::path::PathBuf;

// submodules
mod types;
pub use types::{
    CliCommand, CliGrammar, ExchangeConfigParameters, FlatCliCommand, GenKeysParameters,
    GenKeysPathsSource, GenPubKeysParameters,
};
pub mod parse;
pub mod psk_broker;
pub mod run;

impl CliCommand {
    pub fn parse_and_run_from_env(
        test_helpers: Option<AppServerTest>,
        grammar: CliGrammar,
    ) -> anyhow::Result<()> {
        let (command, tool_name) = Self::parse_from_env(grammar)?;
        command.run(test_helpers, tool_name)
    }
}

/// How to reach a WireGuard PSK Broker
#[derive(Debug, Clone)]
pub enum BrokerInterface {
    /// The PSK Broker is listening on a unix socket at the given path
    ///
    /// active via CLI with `--psk-broker-path <PATH>`
    Socket(PathBuf),

    /// The PSK Broker broker is already connected to this process; a
    /// unix socket stream can be reached at the given file descriptor.
    ///
    /// This is generally used with file descriptor passing.
    ///
    /// active via CLI with `--psk-broker-fd <FD>`
    FileDescriptor(i32),

    /// Create a socketpair(3p), spawn the PSK broker process from within rosenpass,
    /// and hand one end of the socketpair to the broker process via file
    /// descriptor passing to the subprocess
    ///
    /// active via CLI with `--psk-broker-spawn`
    SocketPair,
}
