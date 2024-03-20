use anyhow::{bail, ensure};
use clap::{Parser, Subcommand};
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_secret_memory::file::StoreSecret;
use rosenpass_util::file::{LoadValue, LoadValueB64};
use std::path::PathBuf;

use crate::app_server;
use crate::app_server::AppServer;
use crate::protocol::{SPk, SSk, SymKey};

use super::config;

/// struct holding all CLI arguments for `clap` crate to parse
#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
pub struct CliArgs {
    /// lowest log level to show – log messages at higher levels will be omitted
    #[arg(long = "log-level", value_name = "LOG_LEVEL", group = "log-level")]
    log_level: Option<log::LevelFilter>,

    /// show verbose log output – sets log level to "debug"
    #[arg(short, long, group = "log-level")]
    verbose: bool,

    /// show no log output – sets log level to "error"
    #[arg(short, long, group = "log-level")]
    quiet: bool,

    #[command(subcommand)]
    pub command: CliCommand,
}

impl CliArgs {
    /// returns the log level filter set by CLI args
    /// returns `None` if the user did not specify any log level filter via CLI
    ///
    /// NOTE: the clap feature of ["argument groups"](https://docs.rs/clap/latest/clap/_derive/_tutorial/chapter_3/index.html#argument-relations)
    /// ensures that the user can not specify more than one of the possible log level arguments.
    /// Note the `#[arg("group")]` in the [`CliArgs`] struct.
    pub fn get_log_level(&self) -> Option<log::LevelFilter> {
        if self.verbose {
            return Some(log::LevelFilter::Info);
        }
        if self.quiet {
            return Some(log::LevelFilter::Error);
        }
        if let Some(level_filter) = self.log_level {
            return Some(level_filter);
        }
        None
    }
}

/// represents a command specified via CLI
#[derive(Subcommand, Debug)]
pub enum CliCommand {
    /// Start Rosenpass in server mode and carry on with the key exchange
    ///
    /// This will parse the configuration file and perform the key exchange
    /// with the specified peers. If a peer's endpoint is specified, this
    /// Rosenpass instance will try to initiate a key exchange with the peer,
    /// otherwise only initiation attempts from the peer will be responded to.
    ExchangeConfig { config_file: PathBuf },

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
    #[allow(rustdoc::broken_intra_doc_links)]
    #[allow(rustdoc::invalid_html_tags)]
    Exchange {
        /// public-key <PATH> secret-key <PATH> [listen <ADDR>:<PORT>]... [verbose]
        #[clap(value_name = "OWN_CONFIG")]
        first_arg: String,

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
        rest_of_args: Vec<String>,

        /// Save the parsed configuration to a file before starting the daemon
        #[clap(short, long)]
        config_file: Option<PathBuf>,
    },

    /// Generate a demo config file
    GenConfig {
        config_file: PathBuf,

        /// Forcefully overwrite existing config file
        #[clap(short, long)]
        force: bool,
    },

    /// Generate the keys mentioned in a configFile
    ///
    /// Generates secret- & public-key to their destination. If a config file
    /// is provided then the key file destination is taken from there.
    /// Otherwise the
    GenKeys {
        config_file: Option<PathBuf>,

        /// where to write public-key to
        #[clap(short, long)]
        public_key: Option<PathBuf>,

        /// where to write secret-key to
        #[clap(short, long)]
        secret_key: Option<PathBuf>,

        /// Forcefully overwrite public- & secret-key file
        #[clap(short, long)]
        force: bool,
    },

    /// Deprecated - use gen-keys instead
    #[allow(rustdoc::broken_intra_doc_links)]
    #[allow(rustdoc::invalid_html_tags)]
    Keygen {
        // NOTE yes, the legacy keygen argument initially really accepted "privet-key", not "secret-key"!
        /// public-key <PATH> private-key <PATH>
        args: Vec<String>,
    },

    /// Validate a configuration
    Validate { config_files: Vec<PathBuf> },

    /// Show the rosenpass manpage
    // TODO make this the default, but only after the manpage has been adjusted once the CLI stabilizes
    Man,
}

impl CliCommand {
    /// runs the command specified via CLI
    ///
    /// ## TODO
    /// - This method consumes the [`CliCommand`] value. It might be wise to use a reference...
    pub fn run(self) -> anyhow::Result<()> {
        use CliCommand::*;
        match self {
            Man => {
                let man_cmd = std::process::Command::new("man")
                    .args(["1", "rosenpass"])
                    .status();

                if !(man_cmd.is_ok() && man_cmd.unwrap().success()) {
                    println!(include_str!(env!("ROSENPASS_MAN")));
                }
            }
            GenConfig { config_file, force } => {
                ensure!(
                    force || !config_file.exists(),
                    "config file {config_file:?} already exists"
                );

                config::Rosenpass::example_config().store(config_file)?;
            }

            // Deprecated - use gen-keys instead
            Keygen { args } => {
                log::warn!("The 'keygen' command is deprecated. Please use the 'gen-keys' command instead.");

                let mut public_key: Option<PathBuf> = None;
                let mut secret_key: Option<PathBuf> = None;

                // Manual arg parsing, since clap wants to prefix flags with "--"
                let mut args = args.into_iter();
                loop {
                    match (args.next().as_deref(), args.next()) {
                        (Some("private-key"), Some(opt)) | (Some("secret-key"), Some(opt)) => {
                            secret_key = Some(opt.into());
                        }
                        (Some("public-key"), Some(opt)) => {
                            public_key = Some(opt.into());
                        }
                        (Some(flag), _) => {
                            bail!("Unknown option `{}`", flag);
                        }
                        (_, _) => break,
                    };
                }

                if secret_key.is_none() {
                    bail!("private-key is required");
                }
                if public_key.is_none() {
                    bail!("public-key is required");
                }

                generate_and_save_keypair(secret_key.unwrap(), public_key.unwrap())?;
            }

            GenKeys {
                config_file,
                public_key,
                secret_key,
                force,
            } => {
                // figure out where the key file is specified, in the config file or directly as flag?
                let (pkf, skf) = match (config_file, public_key, secret_key) {
                    (Some(config_file), _, _) => {
                        ensure!(
                            config_file.exists(),
                            "config file {config_file:?} does not exist"
                        );

                        let config = config::Rosenpass::load(config_file)?;

                        (config.public_key, config.secret_key)
                    }
                    (_, Some(pkf), Some(skf)) => (pkf, skf),
                    _ => {
                        bail!("either a config-file or both public-key and secret-key file are required")
                    }
                };

                // check that we are not overriding something unintentionally
                let mut problems = vec![];
                if !force && pkf.is_file() {
                    problems.push(format!(
                        "public-key file {pkf:?} exist, refusing to overwrite it"
                    ));
                }
                if !force && skf.is_file() {
                    problems.push(format!(
                        "secret-key file {skf:?} exist, refusing to overwrite it"
                    ));
                }
                if !problems.is_empty() {
                    bail!(problems.join("\n"));
                }

                // generate the keys and store them in files
                generate_and_save_keypair(skf, pkf)?;
            }

            ExchangeConfig { config_file } => {
                ensure!(
                    config_file.exists(),
                    "config file '{config_file:?}' does not exist"
                );

                let config = config::Rosenpass::load(config_file)?;
                config.validate()?;
                Self::event_loop(config)?;
            }

            Exchange {
                first_arg,
                mut rest_of_args,
                config_file,
            } => {
                rest_of_args.insert(0, first_arg);
                let args = rest_of_args;
                let mut config = config::Rosenpass::parse_args(args)?;

                if let Some(p) = config_file {
                    config.store(&p)?;
                    config.config_file_path = p;
                }
                config.validate()?;
                Self::event_loop(config)?;
            }

            Validate { config_files } => {
                for file in config_files {
                    match config::Rosenpass::load(&file) {
                        Ok(config) => {
                            eprintln!("{file:?} is valid TOML and conforms to the expected schema");
                            match config.validate() {
                                Ok(_) => eprintln!("{file:?} has passed all logical checks"),
                                Err(_) => eprintln!("{file:?} contains logical errors"),
                            }
                        }
                        Err(e) => eprintln!("{file:?} is not valid: {e}"),
                    }
                }
            }
        }

        Ok(())
    }

    fn event_loop(config: config::Rosenpass) -> anyhow::Result<()> {
        // load own keys
        let sk = SSk::load(&config.secret_key)?;
        let pk = SPk::load(&config.public_key)?;

        // start an application server
        let mut srv = std::boxed::Box::<AppServer>::new(AppServer::new(
            sk,
            pk,
            config.listen,
            config.verbosity,
        )?);

        for cfg_peer in config.peers {
            srv.add_peer(
                // psk, pk, outfile, outwg, tx_addr
                cfg_peer.pre_shared_key.map(SymKey::load_b64).transpose()?,
                SPk::load(&cfg_peer.public_key)?,
                cfg_peer.key_out,
                cfg_peer.wg.map(|cfg| app_server::WireguardOut {
                    dev: cfg.device,
                    pk: cfg.peer,
                    extra_params: cfg.extra_params,
                }),
                cfg_peer.endpoint.clone(),
            )?;
        }

        srv.event_loop()
    }
}

/// generate secret and public keys, store in files according to the paths passed as arguments
fn generate_and_save_keypair(secret_key: PathBuf, public_key: PathBuf) -> anyhow::Result<()> {
    let mut ssk = crate::protocol::SSk::random();
    let mut spk = crate::protocol::SPk::random();
    StaticKem::keygen(ssk.secret_mut(), spk.secret_mut())?;
    ssk.store_secret(secret_key)?;
    spk.store(public_key)
}
