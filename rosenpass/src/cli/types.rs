use std::path::PathBuf;

use crate::{config::RosenpassConfig, cli::BrokerInterface};

/// represents a command specified via CLI
#[derive(Debug)]
pub enum CliCommand {
    /// Start Rosenpass key exchanges based on a configuration file
    ///
    /// This will parse the configuration file and perform key exchanges with
    /// the specified peers. If a peer's endpoint is specified, this Rosenpass
    /// instance will try to initiate a key exchange with the peer; otherwise,
    /// only initiation attempts from other peers will be responded to.
    ExchangeConfig(ExchangeConfigParameters),

    /// start Rosenpass key exchanges based on command line arguments
    ///
    /// Also see variant [`CliCommand::ExchangeConfig`] and the
    /// [CLI documentation](crate::config::parse_from_cli)
    Exchange(RosenpassConfig),

    /// generate a demo config file for Rosenpass
    GenConfig(GenConfigParameters),

    /// Generate secret & public key for Rosenpass and write them to file
    ///
    /// TODO: support alternative secret-key name: `public-key <PATH> private-key <PATH>`
    GenKeys(GenKeysParameters),

    /// validate a configuration file
    Validate(Vec<PathBuf>),

    /// generate a manpage and write it to the specified directory
    GenerateManpage(PathBuf),

    /// generate completion file for a shell
    ///
    /// TODO: take `clap_complete::Shell` parameter?
    GenerateShellCompletion(()),

    // print help for the entire application or for the specified subcommand
    Help(Option<FlatCliCommand>),
}
#[derive(Debug)]
pub struct ExchangeConfigParameters {
    pub config: RosenpassConfig,
    pub psk_broker_config: Option<BrokerInterface>,
}
#[derive(Debug)]
pub struct GenConfigParameters {
    /// file path to the where the config is written
    pub config_file: PathBuf,

    /// forcefully overwrite existing config file
    pub force: bool,
}

#[derive(Debug)]
pub struct GenKeysParameters {
    /// from where the [`CliCommand::GenKeys`] will read the paths of the secret/public key files
    pub file_paths: GenKeysPathsSource,
    /// forcefully overwrite public- & secret-key file
    pub force: bool,
}

/// from where the [`CliCommand::GenKeys`] will read the paths of the secret/public key files
#[derive(Debug)]
pub enum GenKeysPathsSource {
    // read the destination of the secret/public key files from the config
    FromConfig(RosenpassConfig),

    /// the user just specified the file paths on the command line
    Raw {
        secret_key_file: PathBuf,
        public_key_file: PathBuf,
    },
}

#[derive(Debug, Hash, PartialEq, Eq)]
pub enum FlatCliCommand {
    ExchangeConfig,
    Exchange,
    GenConfig,
    GenKeys,
    Validate,
    GenerateManpage,
    GenerateShellCompletion,
    Help,
}
// this trait implementation makes sure that [`FlatCliCommand`] never misses any entries
impl From<&CliCommand> for FlatCliCommand {
    fn from(value: &CliCommand) -> Self {
        match value {
            CliCommand::ExchangeConfig(_) => Self::ExchangeConfig,
            CliCommand::Exchange(_) => Self::Exchange,
            CliCommand::GenConfig(_) => Self::GenConfig,
            CliCommand::GenKeys(_) => Self::GenKeys,
            CliCommand::Validate(_) => Self::Validate,
            CliCommand::GenerateManpage(_) => Self::GenerateManpage,
            CliCommand::GenerateShellCompletion(_) => Self::GenerateShellCompletion,
            CliCommand::Help(_) => Self::Help,
        }
    }
}
