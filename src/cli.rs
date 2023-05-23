use anyhow::{bail, ensure};
use clap::Parser;
use std::path::{Path, PathBuf};

use crate::app_server;
use crate::app_server::AppServer;
use crate::util::{LoadValue, LoadValueB64};
use crate::{
    // app_server::{AppServer, LoadValue, LoadValueB64},
    coloring::Secret,
    pqkem::{StaticKEM, KEM},
    protocol::{SPk, SSk, SymKey},
};

use super::config;

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
    /// in the WIREGUARD_EXTRA_ARGS it terminates is not put into the
    /// WireGuard arguments but instead a new peer is created.
    /* Explanation: `first_arg` and `rest_of_args` are combined into one
     * `Vec<String>`. They are only used to trick clap into displaying some
     * guidance on the CLI usage.
     */
    Exchange {
        /// public-key \<PATH> secret-key \<PATH> \[listen \<ADDR>:\<PORT>]... \[verbose]
        #[clap(value_name = "OWN_CONFIG")]
        first_arg: String,

        /// peer public-key \<PATH> \[ENDPOINT] \[PSK] \[OUTFILE] \[WG]
        ///
        /// ENDPOINT := \[endpoint \<HOST/IP>:\<PORT>]
        ///
        /// PSK := \[preshared-key \<PATH>]
        ///
        /// OUTFILE := \[outfile \<PATH>]
        ///
        /// WG := \[wireguard \<WIREGUARD_DEV> \<WIREGUARD_PEER> \[WIREGUARD_EXTRA_ARGS]...]
        #[clap(value_names = [
"peer", "public-key", "<PATH>", "[ENDPOINT]" ,"[PSK]", "[OUTFILE]", "[WG]"            
        ])]
        rest_of_args: Vec<String>,

        /// Save the parsed configuration to a file before starting the daemon
        #[clap(short, long)]
        config_file: Option<PathBuf>,
    },

    /// Generate a demo config file
    GenConfig {
        config_file: PathBuf,

        /// Forecefully overwrite existing config file
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

        /// Forecefully overwrite public- & secret-key file
        #[clap(short, long)]
        force: bool,
    },

    /// Validate a configuration
    Validate { config_files: Vec<PathBuf> },

    /// Show the rosenpass manpage
    // TODO make this the default, but only after the manpage has been adjusted once the CLI stabilizes
    Man,
}

impl Cli {
    pub fn run() -> anyhow::Result<()> {
        let cli = Self::parse();

        use Cli::*;
        match cli {
            Man => {
                let _man_cmd = std::process::Command::new("man")
                    .args(["1", "rosenpass"])
                    .status();
            }
            GenConfig { config_file, force } => {
                ensure!(
                    force || !config_file.exists(),
                    "config file {config_file:?} already exists"
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
                let mut ssk = crate::protocol::SSk::random();
                let mut spk = crate::protocol::SPk::random();

                unsafe {
                    StaticKEM::keygen(ssk.secret_mut(), spk.secret_mut())?;
                    ssk.store_secret(skf)?;
                    spk.store_secret(pkf)?;
                }
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
                                Ok(_) => eprintln!("{file:?} is passed all logical checks"),
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

trait StoreSecret {
    unsafe fn store_secret<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()>;
}

impl<const N: usize> StoreSecret for Secret<N> {
    unsafe fn store_secret<P: AsRef<Path>>(&self, path: P) -> anyhow::Result<()> {
        std::fs::write(path, self.secret())?;
        Ok(())
    }
}
