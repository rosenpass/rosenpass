use clap::Parser;
use rosenpass_util::file::{LoadValue, LoadValueB64};
use std::path::{Path, PathBuf};
use log::{error, ensure, info};
use thiserror::Error;

use crate::app_server;
use crate::app_server::AppServer;
use crate::{
    // app_server::{AppServer, LoadValue, LoadValueB64},
    coloring::Secret,
    pqkem::{StaticKEM, KEM},
    protocol::{SPk, SSk, SymKey},
};

use super::config;

// Custom error type for validation and file-related operations
#[derive(Error, Debug)]
enum RosenpassError {
    #[error("Config file {0:?} already exists")]
    ConfigFileExists(PathBuf),
    #[error("{0:?} does not exist")]
    FileNotFound(PathBuf),
    #[error("Either a config-file or both public-key and secret-key file are required")]
    MissingConfigOrKeys,
    #[error("Public-key file {0:?} exists, refusing to overwrite it")]
    PublicKeyFileExists(PathBuf),
    #[error("Secret-key file {0:?} exists, refusing to overwrite it")]
    SecretKeyFileExists(PathBuf),
    #[error("Config file {0:?} does not exist")]
    ConfigFileNotExists(PathBuf),
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
pub enum Cli {
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

    #[derive(Error, Debug)]
    #[error("Config file {0:?} already exists")]
    ConfigFileExists(PathBuf),
    #[derive(Error, Debug)]
    #[error("{0:?} does not exist")]
    FileNotFound(PathBuf),
    #[derive(Error, Debug)]
    #[error("Either a config-file or both public-key and secret-key file are required")]
    MissingConfigOrKeys,
    #[derive(Error, Debug)]
    #[error("Public-key file {0:?} exists, refusing to overwrite it")]
    PublicKeyFileExists(PathBuf),
    #[derive(Error, Debug)]
    #[error("Secret-key file {0:?} exists, refusing to overwrite it")]
    SecretKeyFileExists(PathBuf),
    #[derive(Error, Debug)]
    #[error("Config file {0:?} does not exist")]
    ConfigFileNotExists(PathBuf),

    /// Validate a configuration
    Validate { config_files: Vec<PathBuf> },

    /// Show the rosenpass manpage
    // TODO make this the default, but only after the manpage has been adjusted once the CLI stabilizes
    Man,
}

impl Cli {
    pub fn run() -> Result<(), RosenpassError> {
        let cli = Self::parse();

        use Cli::*;
        match cli {
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
                    RosenpassError::ConfigFileExists(config_file.clone())
                );

                config::Rosenpass::example_config().store(config_file)?;
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
                            RosenpassError::FileNotFound(config_file.clone())
                        );

                        let config = config::Rosenpass::load(config_file)?;

                        (config.public_key, config.secret_key)
                    }
                    (_, Some(pkf), Some(skf)) => (pkf, skf),
                    _ => {
                        return Err(RosenpassError::MissingConfigOrKeys);
                    }
                };

                // check that we are not overriding something unintentionally
                let mut problems = vec![];
                if !force && pkf.is_file() {
                    problems.push(format!(
                        RosenpassError::PublicKeyFileExists(pkf.clone())
                    ));
                }
                if !force && skf.is_file() {
                    problems.push(format!(
                        RosenpassError::SecretKeyFileExists(skf.clone())
                    ));
                }
                if !problems.is_empty() {
                    return Err(RosenpassError::MissingConfigOrKeys);
                }

                // generate the keys and store them in files
                let mut ssk = crate::protocol::SSk::random();
                let mut spk = crate::protocol::SPk::random();
                StaticKEM::keygen(ssk.secret_mut(), spk.secret_mut())?;

                ssk.store_secret(skf)?;
                spk.store_secret(pkf)?;
            }

            ExchangeConfig { config_file } => {
                ensure!(
                    config_file.exists(),
                    RosenpassError::ConfigFileNotExists(config_file.clone())
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
                            info!("{file:?} is valid TOML and conforms to the expected schema");
                            match config.validate() {
                                Ok(_) => info!("{file:?} is passed all logical checks"),
                                Err(_) => info!("{file:?} contains logical errors"),
                            }
                        }
                        Err(e) => error!("{file:?} is not valid: {e}"),
                    }
                }
            }
        }

        Ok(())
    }

    fn event_loop(config: config::Rosenpass) -> Result<(), RosenpassError> {
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

trait StoreSecret {
    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), RosenpassError>;
}

impl<const N: usize> StoreSecret for Secret<N> {
    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), RosenpassError> {
        fs::write(&path, self.secret()).map_err(|e| {
            RosenpassError::FileWriteError {
                path: path.as_ref().to_path_buf(),
                source: e,
            }
        })?;
        Ok(())
    }
}