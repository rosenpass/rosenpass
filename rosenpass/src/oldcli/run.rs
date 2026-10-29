use std::{
    ops::DerefMut,
    path::{Path, PathBuf},
};

use super::CliCommand;
#[cfg(feature = "experiment_api")]
use crate::oldcli::BrokerInterface;
use crate::{
    app_server::{AppServer, AppServerTest, BrokerPeer},
    config::{PublicKeySource, RosenpassConfig, decode_wg_pubkey_b64, validate::ValidationRecipe},
    internal::{
        cipher_traits::primitives::Kem,
        ciphers::StaticKem,
        secret_memory::file::StoreSecret,
        util::file::{LoadValue, LoadValueB64, StoreValue},
        wireguard_broker::brokers::native_unix::{
            NativeUnixBrokerConfigBaseBuilder, NativeUnixBrokerConfigBaseBuilderError,
        },
    },
    oldcli::GenKeysPathsSource,
    protocol::{
        ProtocolVersion,
        basic_types::{SPk, SSk, SymKey},
        protocol_context::WireGuardKeyBinding,
    },
};
use anyhow::{bail, ensure};

#[cfg(feature = "experiment_api")]
use {
    crate::internal::util::rustix::claim_fd,
    crate::internal::wireguard_broker::WireguardBrokerMio,
    crate::internal::wireguard_broker::brokers::mio_client::MioBrokerClient,
    command_fds::{CommandFdExt, FdMapping},
    log::{error, info},
    mio::net::UnixStream,
    rustix::net::{AddressFamily, SocketFlags, SocketType, socketpair},
    std::os::unix::net,
    std::process::Command,
    std::thread,
};

impl CliCommand {
    pub fn run(&self, test_helpers: Option<AppServerTest>) -> Result<(), anyhow::Error> {
        match &self {
            // TODO: support writing a command line config to a config file
            Self::ExchangeConfig(config) | Self::Exchange(config) => {
                // check configuration
                config.verbosity.apply();
                config.validate_and_print(ValidationRecipe::all())?;
                config.check_usefullness()?;

                // TODO: allow to set per-peer protocol version
                // https://github.com/rosenpass/rosenpass/issues/1196
                let protocol_version = config
                    .supported_protocol_versions
                    .first()
                    .map(|p| *p)
                    .unwrap_or_default();

                const MAX_PSK_SIZE: usize = 1000;

                // load own keys
                #[cfg(not(feature = "experiment_api"))]
                let keypair = Some((
                    SSk::load(config.our_keypair.secret_key_source.get_key_path())?,
                    SPk::load(config.our_keypair.public_key_source.get_key_path())?,
                ));
                #[cfg(feature = "experiment_api")]
                let keypair = {
                    let secret = config
                        .our_keypair
                        .secret_key_source
                        .is_defined()
                        .then(|| SSk::load(config.our_keypair.secret_key_source.get_key_path()))
                        .transpose()?;
                    let public = config
                        .our_keypair
                        .public_key_source
                        .is_defined()
                        .then(|| SPk::load(config.our_keypair.public_key_source.get_key_path()))
                        .transpose()?;
                    match (secret, public) {
                        (None, None) => None,
                        (Some(secret), Some(public)) => Some((secret, public)),
                        _ => bail!("specify either both our secret and public key or none"),
                    }
                };

                // start an application server
                let mut srv = std::boxed::Box::<AppServer>::new(AppServer::new(
                    keypair,
                    config.our_listen_addresses.clone(),
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
                    let (broker_peer, wg_key_binding) = match &cfg_peer.wireguard {
                        Some(wg) => {
                            let peer_cfg = NativeUnixBrokerConfigBaseBuilder::default()
                                .peer_id_b64(&wg.peer)?
                                .interface(wg.device_name.clone())
                                .extra_params_ser(&wg.wireguard_options.to_cli_parameters())?
                                .build()
                                .map_err(cfg_err_map)?;
                            let broker_peer =
                                BrokerPeer::new(broker_store_ptr.clone(), Box::new(peer_cfg));

                            let wg_key_binding = match (protocol_version, &wg.our_wireguard_keypair.try_read()) {
                                (ProtocolVersion::V03, Some(our_wg_pubkey)) => {
                                    Some(WireGuardKeyBinding {
                                        our_wg_pubkey: decode_wg_pubkey_b64(our_wg_pubkey)?,
                                        peer_wg_pubkey: decode_wg_pubkey_b64(&wg.peer)?,
                                    })
                                }
                                (ProtocolVersion::V03, None) => {
                                    unreachable!(
                                        "protocol version 03 but our_wg_pubkey is None – this should be unreachable because config::validate should have caught this case"
                                    );
                                }
                                _ => None,
                            };

                            (Some(broker_peer), wg_key_binding)
                        }
                        None => (None, None),
                    };

                    srv.add_peer(
                        // psk, pk, outfile, outwg, tx_addr
                        cfg_peer
                            .preshared_key
                            .map(|psk| psk.get_key_path())
                            .map(SymKey::load_b64::<MAX_PSK_SIZE, _>)
                            .transpose()?,
                        SPk::load(&cfg_peer.their_public_key.get_key_path())?,
                        cfg_peer
                            .output_to_file
                            .and_then(|o| o.enabled.then(|| o.output_file_path)),
                        broker_peer,
                        cfg_peer.endpoint.clone(),
                        protocol_version,
                        cfg_peer.osk_domain_separator.try_into()?,
                        wg_key_binding,
                    )?;
                }

                srv.event_loop()?;
            }
            Self::GenConfig(parameters) => {
                ensure!(
                    parameters.force || !parameters.config_file.exists(),
                    "config file {:?} already exists",
                    parameters.config_file
                );
                std::fs::write(parameters.config_file, crate::config::EXAMPLE_CONFIG)?;
            }
            Self::GenKeys(parameters) => {
                match parameters.file_paths {
                    GenKeysPathsSource::Raw {
                        secret_key_file,
                        public_key_file,
                    } => generate_and_save_keypair(
                        secret_key_file,
                        public_key_file,
                        parameters.force,
                    )?,
                    GenKeysPathsSource::FromConfig(config) => {
                        generate_and_save_keypair(
                            config.our_keypair.secret_key_source.get_key_path(),
                            config.our_keypair.public_key_source.get_key_path(),
                            // TODO: really force overwrite when reading from config file?
                            // https://github.com/rosenpass/rosenpass/issues/1193
                            parameters.force || true,
                        )?;
                    }
                }
            }
            Self::Validate(paths) => {
                let failed_paths = paths
                    .iter()
                    .map(|path| -> Result<(), &Path> {
                        RosenpassConfig::load_from_file(path)
                            .map_err(|_| &path)?
                            .validate_and_print(ValidationRecipe::all())
                            .map_err(|_| &path)?;
                        Ok(())
                    })
                    .filter_map(|result| result.err())
                    .collect::<Vec<_>>();
                if !failed_paths.is_empty() {
                    bail!(
                        "the following configuration file{s} {is_are} invalid:\n{paths}",
                        s = if failed_paths.len() == 1 { "" } else { "s" },
                        is_are = if failed_paths.len() == 1 { "is" } else { "are" },
                        paths = failed_paths.join("\n")
                    );
                }
            }
            Self::GenerateManpage(out_dir) => {
                todo!(
                    "generating a manpage, see https://github.com/rosenpass/rosenpass/issues/1194"
                );
                // old code by Paul Spooren for reference:
                #[cfg(none)]
                {
                    std::fs::create_dir_all(&out_dir)
                        .expect("Failed to create man pages directory");

                    let cmd = CliArgs::command();
                    let man = clap_mangen::Man::new(cmd.clone());
                    let _ = clap_mangen::generate_to(cmd, &out_dir);

                    let file_path = out_dir.join("rosenpass.1");
                    let mut file =
                        std::fs::File::create(file_path).expect("Failed to create man page file");

                    let _ = man.render_title(&mut file);
                    let _ = man.render_name_section(&mut file);
                    let _ = man.render_synopsis_section(&mut file);
                    let _ = man.render_subcommands_section(&mut file);
                    let _ = man.render_options_section(&mut file);
                    print_custom_man_section("EXIT STATUS", EXIT_STATUS_MAN, &mut file);
                    print_custom_man_section("SEE ALSO", SEE_ALSO_MAN, &mut file);
                    print_custom_man_section("STANDARDS", STANDARDS_MAN, &mut file);
                    print_custom_man_section("AUTHORS", AUTHORS_MAN, &mut file);
                    print_custom_man_section("BUGS", BUGS_MAN, &mut file);
                    return;
                }
            }
            Self::GenerateShellCompletion(shell) => {
                todo!(
                    "generating shell completions, see https://github.com/rosenpass/rosenpass/issues/1195"
                );
                // old implementation by Paul Spooren for reference
                #[cfg(none)]
                if let Some(shell) = args.print_completions {
                    let mut cmd = CliArgs::command();
                    clap_complete::generate(shell, &mut cmd, "rosenpass", &mut std::io::stdout());
                    return;
                }
            }
            Self::Help(subcommand) => {
                todo!("write sensible help output");
            }
        }

        Ok(())
    }

    /// Create the WireGuard PSK broker to be used by
    /// [crate::app_server::AppServer].
    ///
    /// If the `experiment_api`
    /// feature flag is set, then this communicates with a PSK broker
    /// running in a different process as configured via
    /// the `psk_broker_path`, `psk_broker_fd`, and `psk_broker_spawn`
    /// fields.
    ///
    /// If the `experiment_api`
    /// feature flag is not set, then this returns a [NativeUnixBroker],
    /// sending pre-shared keys directly to WireGuard from within this
    /// process.
    #[cfg(feature = "experiment_api")]
    fn create_broker(
        broker_interface: Option<BrokerInterface>,
    ) -> Result<
        Box<dyn WireguardBrokerMio<MioError = anyhow::Error, Error = anyhow::Error> + Send>,
        anyhow::Error,
    > {
        if let Some(interface) = broker_interface {
            let socket = Self::get_broker_socket(interface)?;
            Ok(Box::new(MioBrokerClient::new(socket)))
        } else {
            use crate::internal::wireguard_broker::brokers::native_unix::NativeUnixBroker;

            Ok(Box::new(NativeUnixBroker::new()))
        }
    }

    /// Create the WireGuard PSK broker to be used by
    /// [crate::app_server::AppServer].
    ///
    /// If the `experiment_api`
    /// feature flag is set, then this communicates with a PSK broker
    /// running in a different process as configured via
    /// the `psk_broker_path`, `psk_broker_fd`, and `psk_broker_spawn`
    /// fields.
    ///
    /// If the `experiment_api`
    /// feature flag is not set, then this returns a [NativeUnixBroker],
    /// sending pre-shared keys directly to WireGuard from within this
    /// process.
    #[cfg(not(feature = "experiment_api"))]
    fn create_broker(
        _broker_interface: Option<BrokerInterface>,
    ) -> Result<Box<NativeUnixBroker>, anyhow::Error> {
        Ok(Box::new(NativeUnixBroker::new()))
    }

    /// Used by [Self::create_broker] if the `experiment_api` is configured
    /// to set up the connection with the PSK broker process as configured
    /// via the `psk_broker_path`, `psk_broker_fd`, and `psk_broker_spawn`
    /// fields.
    #[cfg(feature = "experiment_api")]
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
                        parent_fd: theirs,
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
pub fn generate_and_save_keypair(
    secret_key: PathBuf,
    public_key: PathBuf,
    force: bool,
) -> anyhow::Result<()> {
    // check that we are not overriding something unintentionally
    let mut problems = vec![];
    if !force && public_key.is_file() {
        problems.push(format!(
            "public-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(&public_key)?,
        ));
    }
    if !force && secret_key.is_file() {
        problems.push(format!(
            "secret-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(&secret_key)?,
        ));
    }
    if !problems.is_empty() {
        bail!(problems.join("\n"));
    }

    let mut ssk = crate::protocol::basic_types::SSk::random();
    let mut spk = crate::protocol::basic_types::SPk::random();
    StaticKem.keygen(ssk.secret_mut(), spk.deref_mut())?;
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
