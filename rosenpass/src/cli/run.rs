use super::{
    CliCommand, FlatCliCommand, GenKeysPathsSource,
    parse::{
        exchange, exchange_config, generate_config, generate_manpage, genkeys, genpubkeys, validate,
    },
    psk_broker::create_broker,
};
use std::{
    fmt::{self, Display},
    fs::File,
    ops::DerefMut,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};
// #[cfg(feature = "experiment_api")]
use super::BrokerInterface;
use crate::{
    app_server::{AppServer, AppServerTest, BrokerPeer},
    config::{
        KeyFromDisk, KeyFromDiskInner, KeyFromDiskOrB64EncodedString,
        KeyFromDiskOrB64EncodedStringInner, NewFromInner, PublicKeySource, PublicPqKeySource,
        RosenpassConfig, WgKeypairSource, decode_wg_pubkey_b64, validate::ValidationRecipe,
    },
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
                        generate_directory,
                        secret_key_file,
                        public_key_file,
                        wg_secret_key_file,
                    } => generate_and_save_keypair(
                        generate_directory.as_deref(),
                        secret_key_file,
                        public_key_file,
                        wg_secret_key_file.as_deref(),
                        parameters.force,
                    )?,
                    GenKeysPathsSource::FromConfig(config) => {
                        generate_and_save_keypair(
                            // When reading the paths from config, we can generally assume that the
                            // directory already exists because entering a path to a non-existent
                            // directory into a TOML config file is not sth. that so. would do
                            // intuitively.
                            None,
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
                            todo!(
                                "determine whether to create a WG secret key, see https://github.com/rosenpass/rosenpass/issues/1210"
                            ),
                            // TODO: really force overwrite when reading from config file?
                            // https://github.com/rosenpass/rosenpass/issues/1193
                            parameters.force || true,
                        )?;
                    }
                }
            }
            Self::GenPubKeys(parameters) => {
                // TODO: this implementation would work greatly with two separate functions instead
                // of an inline implementation

                // TODO: maybe set umask?
                // https://github.com/rosenpass/rosenpass/issues/1209
                log::warn!(
                    "creating public keys without setting umask, see {}",
                    "https://github.com/rosenpass/rosenpass/issues/1209"
                );

                // create public key directy (this must not exist yet)
                log::info!(
                    "creating directory \"{}\"",
                    parameters.public_keys_directory.display()
                );
                if parameters.public_keys_directory.exists() {
                    bail!("public key directory already exists");
                }
                std::fs::DirBuilder::new()
                    .recursive(true) // historically, rp 0.2.3 also creates parent dirs
                    .create(parameters.public_keys_directory.clone())
                    .map_err(|e| anyhow!(e).context("can not create public keys directory"));

                // copy over the rosenpass public key
                // TODO: historically, the pqpk is just copied over but maybe we want to derive it
                // from the pqsk?
                let old_pq_pubkey = PublicPqKeySource::new(KeyFromDiskInner::Directory(
                    parameters.secret_keys_directory.clone(),
                ))
                .get_key_path();
                let new_pq_pubkey = PublicPqKeySource::new(KeyFromDiskInner::Directory(
                    parameters.public_keys_directory.clone(),
                ))
                .get_key_path();
                log::info!(
                    "copying over public key from \"{}\" to \"{}\"",
                    old_pq_pubkey.display(),
                    new_pq_pubkey.display()
                );
                std::fs::copy(old_pq_pubkey, new_pq_pubkey)
                    .map_err(|e| anyhow!(e).context("can not copy rosenpass public key"));

                // generate the WG public key
                // use a command like this: `wg pubkey $SECRET_FILE  >  $PUBLIC_FILE`
                let wg_keypair = WgKeypairSource {
                    secret_key_source: KeyFromDisk::new(KeyFromDiskInner::Directory(
                        parameters.secret_keys_directory.clone(),
                    )),
                    public_key_source: KeyFromDiskOrB64EncodedString::new(
                        KeyFromDiskOrB64EncodedStringInner::Directory(
                            parameters.public_keys_directory.clone(),
                        ),
                    ),
                };
                let wg_outfile = wg_keypair
                    .public_key_source
                    .get_key_path()
                    // `None` is unreachable because we just defined the key source to
                    // be a path in the previous let binding
                    .expect("unreachable");
                log::info!(
                    "writing WireGuard public key to \"{}\"",
                    wg_outfile.display()
                );
                let outfile = File::create(wg_outfile)
                    .map_err(|e| anyhow!(e).context("can not create wg public key file"))?;
                let exit_code = Command::new("wg")
                    .arg("pubkey")
                    .arg(wg_keypair.secret_key_source.get_key_path())
                    .stdout(Stdio::from(outfile))
                    .status()
                    .map_err(|e| {
                        anyhow!(e).context("can not spawn process \"wg\" to create public key")
                    })?;
                if !exit_code.success() {
                    return Err(anyhow!(
                        "\"wg\" returend with {}",
                        exit_code
                            .code()
                            .map(|s| format!("exit code {s}"))
                            .unwrap_or_else(|| "unknown exit code".to_string())
                    )
                    .context("can not create wg public key"));
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
            Self::Help((subcommand, grammar)) => {
                const INDENT: &str = "    ";
                let bold = anstyle::Style::new().bold();
                let help: Box<dyn Display> = match subcommand {
                    Some(FlatCliCommand::ExchangeConfig) => {
                        Box::new(exchange_config::help(INDENT, *grammar))
                    }
                    Some(FlatCliCommand::Exchange) => Box::new(exchange::help(INDENT, *grammar)),
                    Some(FlatCliCommand::GenConfig) => {
                        Box::new(generate_config::help(INDENT, *grammar)?)
                    }
                    Some(FlatCliCommand::GenKeys) => Box::new(genkeys::help(INDENT, *grammar)),
                    Some(FlatCliCommand::GenPubKeys) => {
                        Box::new(genpubkeys::help(INDENT, *grammar)?)
                    }
                    Some(FlatCliCommand::Validate) => Box::new(validate::help(INDENT, *grammar)?),
                    Some(FlatCliCommand::GenerateManpage) => {
                        Box::new(generate_manpage::help(INDENT, *grammar))
                    }
                    Some(FlatCliCommand::GenerateShellCompletion) => {
                        todo!("shell completions are not yet supported");
                        // anstream::eprintln!("{tool_name} {}", generate_shell_completion::help(INDENT))
                    }
                    // there is no help on help on help on help...
                    Some(FlatCliCommand::Help) => unreachable!(),
                    None => Box::new(help(INDENT)),
                };
                anstream::eprint!("{bold}{tool_name}{bold:#} {help}");
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
    generate_directory: Option<&Path>,
    secret_key_file: &Path,
    public_key_file: &Path,
    wg_secret_key: Option<&Path>,
    force: bool,
) -> anyhow::Result<()> {
    // check that we are not overriding something unintentionally
    let mut problems = vec![];
    if !force && public_key_file.exists() {
        problems.push(format!(
            "public-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(public_key_file)?,
        ));
    }
    if !force && secret_key_file.exists() {
        problems.push(format!(
            "secret-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(secret_key_file)?,
        ));
    }
    if secret_key_file == public_key_file {
        problems.push("secret key file and public key file have the same path".into());
    }
    if !problems.is_empty() {
        bail!(problems.join("\n"));
    }

    // TODO: maybe set umask?
    // https://github.com/rosenpass/rosenpass/issues/1209
    log::warn!(
        "creating secret/public keys without setting umask, see {}",
        "https://github.com/rosenpass/rosenpass/issues/1209"
    );

    // create directory
    if let Some(generate_directory) = generate_directory {
        log::info!("creating directory \"{}\"", generate_directory.display());
        if generate_directory.exists() {
            bail!(
                "can not create key  directory \"{}\" because it already exists",
                generate_directory.display()
            );
        }
        std::fs::DirBuilder::new()
            .recursive(true) // historically, rp 0.2.3 also creates parent dirs
            .create(generate_directory.clone())
            .map_err(|e| anyhow!(e).context("can not create keys directory"));
    }

    // generate and write secret key and public key
    log::info!("generating static keypair");
    let mut ssk = crate::protocol::basic_types::SSk::random();
    let mut spk = crate::protocol::basic_types::SPk::random();
    StaticKem.keygen(ssk.secret_mut(), spk.deref_mut())?;
    log::info!(
        "storing static secret key to \"{}\"",
        secret_key_file.display()
    );
    ssk.store_secret(secret_key_file)?;
    log::info!(
        "storing static public key to \"{}\"",
        public_key_file.display()
    );
    spk.store(public_key_file)?;

    // generate WireGuard secret key with command line this: `wg genkey > $OUTFILE`
    if let Some(wg_secret_key) = wg_secret_key {
        log::info!(
            "generating WireGuard secret key and writing it to \"{}\"",
            wg_secret_key.display()
        );
        let outfile = File::create(wg_secret_key)
            .map_err(|e| anyhow!(e).context("can not create wg secret key file"))?;
        let exit_code = Command::new("wg")
            .arg("genkey")
            .stdout(Stdio::from(outfile))
            .status()
            .map_err(|e| anyhow!(e).context("can not spawn process \"wg\" to create secret key"))?;
        if !exit_code.success() {
            return Err(anyhow!(
                "\"wg\" returend with {}",
                exit_code
                    .code()
                    .map(|s| format!("exit code {s}"))
                    .unwrap_or_else(|| "unknown exit code".to_string())
            )
            .context("can not create wg secret key"));
        }
    }

    // return
    Ok(())
}

/// called by [`CliCommand::run`]
pub fn exchange_implementation(
    config: &RosenpassConfig,
    psk_broker_config: Option<BrokerInterface>,
    test_helpers: Option<AppServerTest>,
) -> anyhow::Result<()> {
    // check configuration
    if !test_helpers
        .as_ref()
        .map(|th| th.skip_init_logging)
        .unwrap_or(false)
    {
        config.verbosity.apply();
    }
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
                .map(|our|our.get_public_key())
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
                .map(|psk| psk.get_key_file_path())
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
