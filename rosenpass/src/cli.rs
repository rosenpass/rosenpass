use anyhow::{bail, ensure, Context};
use clap::{Parser, Subcommand};
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_secret_memory::file::StoreSecret;
use rosenpass_util::file::{LoadValue, LoadValueB64, StoreValue};
use rosenpass_wireguard_broker::brokers::native_unix::{
    NativeUnixBroker, NativeUnixBrokerConfigBaseBuilder, NativeUnixBrokerConfigBaseBuilderError,
};
use std::ops::DerefMut;
use std::path::PathBuf;

use crate::app_server::AppServerTest;
use crate::app_server::{AppServer, BrokerPeer};
use crate::protocol::{SPk, SSk, SymKey};

use super::config;

#[cfg(feature = "experiment_broker_api")]
use {
    command_fds::{CommandFdExt, FdMapping},
    log::{error, info},
    mio::net::UnixStream,
    rosenpass_util::fd::claim_fd,
    rosenpass_wireguard_broker::brokers::mio_client::MioBrokerClient,
    rosenpass_wireguard_broker::WireguardBrokerMio,
    rustix::fd::AsRawFd,
    rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType},
    std::os::unix::net,
    std::process::Command,
    std::thread,
};

/// enum representing a choice of interface to a WireGuard broker
#[derive(Debug)]
pub enum BrokerInterface {
    Socket(PathBuf),
    FileDescriptor(i32),
    SocketPair,
}

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

    #[command(flatten)]
    #[cfg(feature = "experiment_api")]
    api: crate::api::cli::ApiCli,

    /// path of the wireguard_psk broker socket to connect to
    #[cfg(feature = "experiment_broker_api")]
    #[arg(long, group = "psk-broker-specs")]
    psk_broker_path: Option<PathBuf>,

    /// fd of the wireguard_spk broker socket to connect to
    ///
    /// when this command is called from another process, the other process can open and bind the
    /// Unix socket for the psk broker connection to use themselves, passing it to this process --
    /// in Rust this can be achieved using the
    /// [command-fds](https://docs.rs/command-fds/latest/command_fds/) crate
    #[cfg(feature = "experiment_broker_api")]
    #[arg(long, group = "psk-broker-specs")]
    psk_broker_fd: Option<i32>,

    /// spawn a psk broker locally using a socket pair
    #[cfg(feature = "experiment_broker_api")]
    #[arg(short, long, group = "psk-broker-specs")]
    psk_broker_spawn: bool,

    #[command(subcommand)]
    pub command: CliCommand,
}

impl CliArgs {
    pub fn apply_to_config(&self, _cfg: &mut config::Rosenpass) -> anyhow::Result<()> {
        #[cfg(feature = "experiment_api")]
        self.api.apply_to_config(_cfg)?;
        Ok(())
    }

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
            return Some(log::LevelFilter::Warn);
        }
        if let Some(level_filter) = self.log_level {
            return Some(level_filter);
        }
        None
    }

    #[cfg(feature = "experiment_broker_api")]
    /// returns the broker interface set by CLI args
    /// returns `None` if the `experiment_broker_api` feature isn't enabled
    pub fn get_broker_interface(&self) -> Option<BrokerInterface> {
        if let Some(path_ref) = self.psk_broker_path.as_ref() {
            Some(BrokerInterface::Socket(path_ref.to_path_buf()))
        } else if let Some(fd) = self.psk_broker_fd {
            Some(BrokerInterface::FileDescriptor(fd))
        } else if self.psk_broker_spawn {
            Some(BrokerInterface::SocketPair)
        } else {
            None
        }
    }

    #[cfg(not(feature = "experiment_broker_api"))]
    /// returns the broker interface set by CLI args
    /// returns `None` if the `experiment_broker_api` feature isn't enabled
    pub fn get_broker_interface(&self) -> Option<BrokerInterface> {
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

impl CliArgs {
    /// runs the command specified via CLI
    ///
    /// ## TODO
    /// - This method consumes the [`CliCommand`] value. It might be wise to use a reference...
    pub fn run(
        self,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> anyhow::Result<()> {
        use CliCommand::*;
        match &self.command {
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
                    *force || !config_file.exists(),
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
                let mut args = args.iter();
                loop {
                    match (args.next().map(|x| x.as_str()), args.next()) {
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
                        let keypair = config
                            .keypair
                            .context("Config file present, but no keypair is specified.")?;

                        (keypair.public_key, keypair.secret_key)
                    }
                    (_, Some(pkf), Some(skf)) => (pkf.clone(), skf.clone()),
                    _ => {
                        bail!("either a config-file or both public-key and secret-key file are required")
                    }
                };

                // check that we are not overriding something unintentionally
                let mut problems = vec![];
                if !force && pkf.is_file() {
                    problems.push(format!(
                        "public-key file {:?} exists, refusing to overwrite",
                        std::fs::canonicalize(&pkf)?,
                    ));
                }
                if !force && skf.is_file() {
                    problems.push(format!(
                        "secret-key file {:?} exists, refusing to overwrite",
                        std::fs::canonicalize(&skf)?,
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

                let mut config = config::Rosenpass::load(config_file)?;
                config.validate()?;
                self.apply_to_config(&mut config)?;
                config.check_usefullness()?;

                Self::event_loop(config, broker_interface, test_helpers)?;
            }

            Exchange {
                first_arg,
                rest_of_args,
                config_file,
            } => {
                let mut rest_of_args = rest_of_args.clone();
                rest_of_args.insert(0, first_arg.clone());
                let args = rest_of_args;
                let mut config = config::Rosenpass::parse_args(args)?;

                if let Some(p) = config_file {
                    config.store(p)?;
                    config.config_file_path.clone_from(p);
                }
                config.validate()?;
                self.apply_to_config(&mut config)?;
                config.check_usefullness()?;

                Self::event_loop(config, broker_interface, test_helpers)?;
            }

            Validate { config_files } => {
                for file in config_files {
                    match config::Rosenpass::load(file) {
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

    fn event_loop(
        config: config::Rosenpass,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> anyhow::Result<()> {
        const MAX_PSK_SIZE: usize = 1000;

        // load own keys
        let keypair = config
            .keypair
            .as_ref()
            .map(|kp| -> anyhow::Result<_> {
                let sk = SSk::load(&kp.secret_key)?;
                let pk = SPk::load(&kp.public_key)?;
                Ok((sk, pk))
            })
            .transpose()?;

        // start an application server
        let mut srv = std::boxed::Box::<AppServer>::new(AppServer::new(
            keypair,
            config.listen.clone(),
            config.verbosity,
            test_helpers,
        )?);

        config.apply_to_app_server(&mut srv)?;

        let broker = Self::create_broker(broker_interface)?;
        let broker_store_ptr = srv.register_broker(broker)?;

        fn cfg_err_map(e: NativeUnixBrokerConfigBaseBuilderError) -> anyhow::Error {
            anyhow::Error::msg(format!("NativeUnixBrokerConfigBaseBuilderError: {:?}", e))
        }

        for cfg_peer in config.peers {
            let broker_peer = if let Some(wg) = &cfg_peer.wg {
                let peer_cfg = NativeUnixBrokerConfigBaseBuilder::default()
                    .peer_id_b64(&wg.peer)?
                    .interface(wg.device.clone())
                    .extra_params_ser(&wg.extra_params)?
                    .build()
                    .map_err(cfg_err_map)?;

                let broker_peer = BrokerPeer::new(broker_store_ptr.clone(), Box::new(peer_cfg));

                Some(broker_peer)
            } else {
                None
            };

            srv.add_peer(
                // psk, pk, outfile, outwg, tx_addr
                cfg_peer
                    .pre_shared_key
                    .map(SymKey::load_b64::<MAX_PSK_SIZE, _>)
                    .transpose()?,
                SPk::load(&cfg_peer.public_key)?,
                cfg_peer.key_out,
                broker_peer,
                cfg_peer.endpoint.clone(),
            )?;
        }

        srv.event_loop()
    }

    #[cfg(feature = "experiment_broker_api")]
    fn create_broker(
        broker_interface: Option<BrokerInterface>,
    ) -> Result<
        Box<dyn WireguardBrokerMio<MioError = anyhow::Error, Error = anyhow::Error>>,
        anyhow::Error,
    > {
        if let Some(interface) = broker_interface {
            let socket = Self::get_broker_socket(interface)?;
            Ok(Box::new(MioBrokerClient::new(socket)))
        } else {
            Ok(Box::new(NativeUnixBroker::new()))
        }
    }

    #[cfg(not(feature = "experiment_broker_api"))]
    fn create_broker(
        _broker_interface: Option<BrokerInterface>,
    ) -> Result<Box<NativeUnixBroker>, anyhow::Error> {
        Ok(Box::new(NativeUnixBroker::new()))
    }

    #[cfg(feature = "experiment_broker_api")]
    fn get_broker_socket(broker_interface: BrokerInterface) -> Result<UnixStream, anyhow::Error> {
        // Connect to the psk broker unix socket if one was specified
        // OR OTHERWISE spawn the psk broker and use socketpair(2) to connect with them
        match broker_interface {
            BrokerInterface::Socket(broker_path) => Ok(UnixStream::connect(broker_path)?),
            BrokerInterface::FileDescriptor(broker_fd) => {
                // mio::net::UnixStream doesn't implement From<OwnedFd>, so we have to go through std
                let sock = net::UnixStream::from(claim_fd(broker_fd)?);
                sock.set_nonblocking(true)?;
                Ok(UnixStream::from_std(sock))
            }
            BrokerInterface::SocketPair => {
                // Form a socketpair for communicating to the broker
                let (ours, theirs) = socketpair(
                    AddressFamily::UNIX,
                    SocketType::STREAM,
                    SocketFlags::empty(),
                    None,
                )?;

                // Setup our end of the socketpair
                let ours = net::UnixStream::from(ours);
                ours.set_nonblocking(true)?;

                // Start the PSK broker
                let mut child = Command::new("rosenpass-wireguard-broker-socket-handler")
                    .args(["--stream-fd", "3"])
                    .fd_mappings(vec![FdMapping {
                        parent_fd: theirs.as_raw_fd(),
                        child_fd: 3,
                    }])?
                    .spawn()?;

                // Handle the PSK broker crashing
                thread::spawn(move || {
                    let status = child.wait();

                    if let Ok(status) = status {
                        if status.success() {
                            // Maybe they are doing double forking?
                            info!("PSK broker exited.");
                        } else {
                            error!("PSK broker exited with an error ({status:?})");
                        }
                    } else {
                        error!("Wait on PSK broker process failed ({status:?})");
                    }
                });

                Ok(UnixStream::from_std(ours))
            }
        }
    }
}

/// generate secret and public keys, store in files according to the paths passed as arguments
fn generate_and_save_keypair(secret_key: PathBuf, public_key: PathBuf) -> anyhow::Result<()> {
    let mut ssk = crate::protocol::SSk::random();
    let mut spk = crate::protocol::SPk::random();
    StaticKem::keygen(ssk.secret_mut(), spk.deref_mut())?;
    ssk.store_secret(secret_key)?;
    spk.store(public_key)
}

#[cfg(feature = "internal_testing")]
pub mod testing {
    use super::*;

    pub fn generate_and_save_keypair(
        secret_key: PathBuf,
        public_key: PathBuf,
    ) -> anyhow::Result<()> {
        super::generate_and_save_keypair(secret_key, public_key)
    }
}
