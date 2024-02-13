use std::io::{BufReader, Read};
use std::os::unix::net::UnixStream;
use std::path::PathBuf;
use std::process::Command;
use std::thread;

use anyhow::{bail, ensure, Context};
use clap::Parser;
use command_fds::{CommandFdExt, FdMapping};
use log::{error, info};
use rustix::fd::AsRawFd;
use rustix::net::{socketpair, AddressFamily, SocketFlags, SocketType};

use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_secret_memory::file::StoreSecret;
use rosenpass_secret_memory::Public;
use rosenpass_util::b64::b64_reader;
use rosenpass_util::file::{LoadValue, LoadValueB64};

use crate::app_server;
use crate::app_server::AppServer;
use crate::protocol::{SPk, SSk, SymKey};

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
        /// - [ ] Janepie
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

impl Cli {
    pub fn run() -> anyhow::Result<()> {
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

        // Connect to the psk broker unix socket if one was specified
        // OR OTHERWISE pawn the psk broker and use socketpair(2) to connect with them
        let psk_broker_socket = if let Some(broker_path) = config.psk_broker {
            let sock = UnixStream::connect(broker_path)?;
            sock.set_nonblocking(true)?;
            sock
        } else {
            let (ours, theirs) = socketpair(
                AddressFamily::UNIX,
                SocketType::STREAM,
                SocketFlags::empty(),
                None,
            )?;

            // Setup our end of the socketpair
            let ours = UnixStream::from(ours);
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

            ours
        };

        // start an application server
        let mut srv = std::boxed::Box::<AppServer>::new(AppServer::new(
            sk,
            pk,
            config.listen,
            psk_broker_socket,
            config.verbosity,
        )?);

        for cfg_peer in config.peers {
            srv.add_peer(
                // psk, pk, outfile, outwg, tx_addr
                cfg_peer.pre_shared_key.map(SymKey::load_b64).transpose()?,
                SPk::load(&cfg_peer.public_key)?,
                cfg_peer.key_out,
                cfg_peer
                    .wg
                    .map(|cfg| -> anyhow::Result<_> {
                        let b64pk = &cfg.peer;
                        let mut pk = Public::zero();
                        b64_reader(BufReader::new(b64pk.as_bytes()))
                            .read_exact(&mut pk.value)
                            .with_context(|| {
                                format!("Could not decode base64 public key: '{b64pk}'")
                            })?;

                        Ok(app_server::WireguardOut {
                            pk,
                            dev: cfg.device,
                            extra_params: cfg.extra_params,
                        })
                    })
                    .transpose()?,
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
    spk.store_secret(public_key)
}
