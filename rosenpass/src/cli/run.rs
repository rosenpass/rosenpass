#[cfg(feature = "experiment_api")]
use super::psk_broker::get_broker_socket;
use super::{
    CliCommand, FlatCliCommand, GenKeysPathsSource,
    parse::{
        exchange, exchange_config, generate_config, generate_manpage, generate_shell_completion,
        genkeys, validate,
    },
    psk_broker::create_broker,
};
use std::{
    fmt::{self, Display},
    ops::DerefMut,
    path::{Path, PathBuf},
};
// #[cfg(feature = "experiment_api")]
use super::BrokerInterface;
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
    protocol::{
        ProtocolVersion,
        basic_types::{SPk, SSk, SymKey},
        protocol_context::WireGuardKeyBinding,
    },
};
use anyhow::{anyhow, bail, ensure};

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
    pub fn run(
        &self,
        test_helpers: Option<AppServerTest>,
        tool_name: String,
    ) -> Result<(), anyhow::Error> {
        match &self {
            // TODO: support writing a command line config to a config file
            Self::ExchangeConfig(config) => {
                exchange_implementation(
                    &config.config,
                    config.psk_broker_config.clone(),
                    test_helpers,
                )?;
            }
            Self::Exchange(config) => exchange_implementation(config, None, test_helpers)?,
            Self::GenConfig(parameters) => {
                ensure!(
                    parameters.force || !parameters.config_file.exists(),
                    "config file {:?} already exists",
                    parameters.config_file
                );
                std::fs::write(&parameters.config_file, crate::config::EXAMPLE_CONFIG)?;
            }
            Self::GenKeys(parameters) => {
                match &parameters.file_paths {
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
                            config
                                .our_keypair
                                .secret_key_source
                                .get_key_path()
                                .as_path(),
                            config
                                .our_keypair
                                .public_key_source
                                .get_key_path()
                                .as_path(),
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
                    .map(|path| -> Result<(), &PathBuf> {
                        RosenpassConfig::load_from_file(path)
                            .map_err(|_| path)?
                            .validate_and_print(ValidationRecipe::all())
                            .map_err(|_| path)?;
                        Ok(())
                    })
                    .filter_map(|result| result.err())
                    .collect::<Vec<&PathBuf>>();
                if !failed_paths.is_empty() {
                    bail!(
                        "the following configuration file{s} {is_are} invalid:\n{paths}",
                        s = if failed_paths.len() == 1 { "" } else { "s" },
                        is_are = if failed_paths.len() == 1 { "is" } else { "are" },
                        paths = failed_paths
                            .iter()
                            .map(|p| p.display().to_string())
                            .collect::<Vec<String>>()
                            .join("\n")
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
                const INDENT: &str = "    ";
                match subcommand {
                    Some(FlatCliCommand::ExchangeConfig) => {
                        anstream::eprint!("{tool_name} {}", exchange_config::help(INDENT))
                    }
                    Some(FlatCliCommand::Exchange) => {
                        anstream::eprint!("{tool_name} {}", exchange::help(INDENT))
                    }
                    Some(FlatCliCommand::GenConfig) => {
                        anstream::eprint!("{tool_name} {}", generate_config::help(INDENT))
                    }
                    Some(FlatCliCommand::GenKeys) => {
                        anstream::eprint!("{tool_name} {}", genkeys::help(INDENT))
                    }
                    Some(FlatCliCommand::Validate) => {
                        anstream::eprint!("{tool_name} {}", validate::help(INDENT))
                    }
                    Some(FlatCliCommand::GenerateManpage) => {
                        anstream::eprint!("{tool_name} {}", generate_manpage::help(INDENT))
                    }
                    Some(FlatCliCommand::GenerateShellCompletion) => {
                        todo!("shell completions are not yet supported");
                        // anstream::eprintln!("{tool_name} {}", generate_shell_completion::help(INDENT))
                    }
                    Some(FlatCliCommand::Help) => unreachable!(),
                    None => anstream::eprint!("{tool_name} {}", help(INDENT)),
                }
            }
        }

        Ok(())
    }
}

/// returns the help message for the `rosenpass` command
/// 
/// TODO: print for `rp`
#[rustfmt::skip]
pub fn help<'a>(indent: &'a str) -> impl Display + 'a {
    let i = indent; // shorter, save a bit of space in the code
    fmt::from_fn(move |f| {
        todo!("help message for rosenpass command")
    })
}

/// generate secret and public keys, store in files according to the paths passed as arguments
pub fn generate_and_save_keypair(
    secret_key: &Path,
    public_key: &Path,
    force: bool,
) -> anyhow::Result<()> {
    // check that we are not overriding something unintentionally
    let mut problems = vec![];
    if !force && public_key.is_file() {
        problems.push(format!(
            "public-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(public_key)?,
        ));
    }
    if !force && secret_key.is_file() {
        problems.push(format!(
            "secret-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(secret_key)?,
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

/// called by [`CliCommand::run`]
pub fn exchange_implementation(
    config: &RosenpassConfig,
    psk_broker_config: Option<BrokerInterface>,
    test_helpers: Option<AppServerTest>,
) -> anyhow::Result<()> {
    // check configuration
    config.verbosity.apply();
    config.validate_and_print(ValidationRecipe::all())?;
    config.check_usefullness()?;

    // TODO: allow to set per-peer protocol version
    // https://github.com/rosenpass/rosenpass/issues/1196
    let protocol_version = config
        .supported_protocol_versions
        .first()
        .copied()
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

    let broker = create_broker(psk_broker_config)?;
    let broker_store_ptr = srv.register_broker(broker)?;

    fn cfg_err_map(e: NativeUnixBrokerConfigBaseBuilderError) -> anyhow::Error {
        anyhow::Error::msg(format!("NativeUnixBrokerConfigBaseBuilderError: {:?}", e))
    }

    for cfg_peer in config.peers.iter() {
        let (broker_peer, wg_key_binding) = match &cfg_peer.wireguard {
            Some(wg) => {
                let our_wg_pubkey = wg.our_wireguard_keypair.as_ref()
                .map(|our|our.get_pubkey())
                .map(|key| key.get_inline_key().expect("not yet implemented: read WireGuard keypair from other sources than inline base64-encoded"));
                let their_wg_pubkey = wg.their_wireguard_public_key.get_inline_key().ok_or_else(
                    || {
                        todo!(
                            "read WireGuard keypair from other sources than inline base64-encoded"
                        )
                    },
                )?;
                let peer_cfg = NativeUnixBrokerConfigBaseBuilder::default()
                    .peer_id_b64(&their_wg_pubkey)?
                    .interface(wg.device_name.clone())
                    .extra_params_ser(&wg.wireguard_options.to_cli_parameters())?
                    .build()
                    .map_err(cfg_err_map)?;
                let broker_peer = BrokerPeer::new(broker_store_ptr.clone(), Box::new(peer_cfg));

                let wg_key_binding = match (protocol_version, &our_wg_pubkey) {
                    (ProtocolVersion::V03, Some(our_wg_pubkey)) => Some(WireGuardKeyBinding {
                        our_wg_pubkey: decode_wg_pubkey_b64(our_wg_pubkey)?,
                        peer_wg_pubkey: decode_wg_pubkey_b64(&their_wg_pubkey)?,
                    }),
                    (ProtocolVersion::V03, None) => {
                        unreachable!(
                            "{} – {}",
                            "protocol version 03 but our_wg_pubkey is None",
                            "this should be unreachable because config::validate should have caught this case"
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
                .as_ref()
                .map(|psk| psk.get_key_path())
                .map(SymKey::load_b64::<MAX_PSK_SIZE, _>)
                .transpose()?,
            SPk::load(cfg_peer.their_public_key.get_key_path())?,
            cfg_peer
                .output_to_file
                .as_ref()
                .and_then(|o| o.enabled.then(|| o.output_file_path.clone())),
            broker_peer,
            cfg_peer.endpoint.clone(),
            protocol_version,
            cfg_peer.osk_domain_separator.clone().try_into()?,
            wg_key_binding,
        )?;
    }

    srv.event_loop()
}
