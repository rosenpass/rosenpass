use clap::Args;
use clap::{Parser, Subcommand};
use clap_verbosity_flag::Verbosity;

use std::path::PathBuf;

#[derive(Parser)]
#[command(author, version, about)]
/// rosenpass performs cryptographic key exchanges that are secure against
/// quantum-computers and then outputs the keys. These keys can then be passed
/// to various services, such as wireguard or other vpn services, as
/// pre-shared-keys to achieve security against attackers with quantum
/// computers.
///
/// This is a research project and quantum computers are not thought to become
/// practical in fewer than ten years. If you are not specifically tasked with
/// developing post-quantum secure systems, you probably do not need this tool.
pub struct Cli {
    #[command(flatten)]
    pub verbose: Verbosity,

    #[command(subcommand)]
    pub command: Commands,

    /// path of the wireguard_psk broker socket to connect to
    #[cfg(feature = "experiment_api")]
    #[arg(long, group = "psk-broker-specs")]
    pub psk_broker_path: Option<PathBuf>,

    /// fd of the wireguard_spk broker socket to connect to
    ///
    /// when this command is called from another process, the other process can open and bind the
    /// Unix socket for the psk broker connection to use themselves, passing it to this process --
    /// in Rust this can be achieved using the
    /// [command-fds](https://docs.rs/command-fds/latest/command_fds/) crate
    #[cfg(feature = "experiment_api")]
    #[arg(long, group = "psk-broker-specs")]
    pub psk_broker_fd: Option<i32>,

    /// spawn a psk broker locally using a socket pair
    #[cfg(feature = "experiment_api")]
    #[arg(short, long, group = "psk-broker-specs")]
    pub psk_broker_spawn: bool,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Exchange a config file with peers
    ///
    /// Start Rosenpass in server mode and carry on with the key exchange
    /// This will parse the configuration file and perform the key exchange
    /// with the specified peers. If a peer's endpoint is specified, this
    /// Rosenpass instance will try to initiate a key exchange with the peer,
    /// otherwise only initiation attempts from the peer will be responded to.
    ExchangeConfig(ExchangeConfig),

    /// Start in daemon mode, performing key exchanges
    ///
    /// The configuration is read from the command line. The `peer` token
    /// always separates multiple peers, e. g. if the token `peer` appears
    /// in the WIREGUARD_EXTRA_ARGS it is not put into the WireGuard arguments
    /// but instead a new peer is created.
    /* Explanation: `first_arg` and `rest_of_args` are combined into one
     * `Vec<String>`. They are only used to trick clap into displaying some
     * guidance on the CLI usage.
     */
    Exchange(Exchange),

    /// Generate a new config file
    GenConfig(GenConfig),

    /// Generate the keys mentioned in a configFile
    ///
    /// Generates secret- & public-key to their destination. If a config file
    /// is provided then the key file destination is taken from there.
    /// Otherwise the
    GenKeys(GenKeys),

    /// Validate one or more config files
    Validate(Validate),

    /// Deprecated - use gen-keys instead
    Keygen(Keygen),

    /// Show man page
    Man(Man),
}

#[derive(Args)]
pub struct ExchangeConfig {
    /// The config file to exchange
    pub config_file: PathBuf,
}

#[derive(Args)]
pub struct Exchange {
    /// public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose]
    #[clap(value_name = "OWN_CONFIG")]
    pub first_arg: String,

    /// peer public-key <PATH> [ENDPOINT] [PSK] [OUTFILE] [WG]
    ///
    /// ENDPOINT := endpoint <HOST/IP>:<PORT>
    ///
    /// PSK := preshared-key <PATH>
    ///
    /// OUTFILE := outfile <PATH>
    ///
    /// WG := wireguard <WIREGUARD_DEV> <WIREGUARD_PEER> [WIREGUARD_EXTRA_ARGS]...
    #[clap(value_name = "PEERS")]
    pub rest_of_args: Vec<String>,

    #[clap(short, long)]
    pub config_file: Option<PathBuf>,
}

#[derive(Args)]
/// Generate a demo config file
pub struct GenConfig {
    pub config_file: PathBuf,

    /// Forcefully overwrite existing config file
    #[clap(short, long)]
    pub force: bool,
}

#[derive(Args)]
pub struct GenKeys {
    pub config_file: Option<PathBuf>,

    #[clap(short, long)]
    /// Where to write public-key to
    pub public_key: Option<PathBuf>,

    /// Where to write secret-key to
    #[clap(short, long)]
    pub secret_key: Option<PathBuf>,

    /// Forcefully overwrite public- & secret-key file
    #[clap(short, long)]
    pub force: bool,
}

#[derive(Args)]
/// Deprecated - use gen-keys instead
pub struct Keygen {
    pub args: Vec<String>,
}

#[derive(Args)]
/// Validate configuration file(s)
pub struct Validate {
    pub config_files: Vec<PathBuf>,
}

#[derive(Args)]
/// Show the rosenpass manpage
pub struct Man {}
