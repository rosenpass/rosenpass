use std::{ffi::OsString, fmt::Debug};

use crate::{
    app_server::{AppServer, AppServerTest, BrokerPeer},
    cli::{BrokerInterface, psk_broker::create_broker},
    config::{
        DeviceWireguardOptions, KeyFromDiskOrB64EncodedString, KeyFromDiskOrB64EncodedStringInner,
        PublicKeySource, PublicWgKeySource, RosenpassConfig, WgDeviceCreateOptions,
        decode_wg_pubkey_b64, parse_from_toml::util::GuaranteedUnwrap, validate::ValidationRecipe,
    },
    internal::{
        util::file::{LoadValue, LoadValueB64},
        wireguard_broker::brokers::native_unix::{
            NativeUnixBrokerConfigBaseBuilder, NativeUnixBrokerConfigBaseBuilderError,
        },
    },
    protocol::{
        ProtocolVersion,
        basic_types::{PublicSymKey, SPk, SSk, SymKey},
        protocol_context::WireGuardKeyBinding,
    },
};
use anyhow::{anyhow, bail};
use base64ct::Encoding;
/// a simple type which only implements [`Drop`] to ensure that the WireGuard device is destroyed
/// on program exit
pub struct RunningWireGuardDevice {
    device_name: String,
    // NOTE: when adding additional attributes, add them to the `Debug` implementation
}
impl Debug for RunningWireGuardDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "a running WireGuard device named \"{}\"",
            self.device_name
        )
    }
}
impl Drop for RunningWireGuardDevice {
    /// destroy the device – but never panic
    fn drop(&mut self) {
        let name = self.device_name.as_str();
        log::info!("destroying WireGuard device \"{name}\"");
        let mut cmd = {
            #[cfg(target_os = "linux")]
            {
                // ip link del dev $(enquote "${dev}") || true
                let mut cmd = std::process::Command::new("ip");
                cmd.args(["link", "del", "dev", name]);
                cmd
            }
            #[cfg(target_os = "freebsd")]
            {
                // ifconfig $(enquote "${dev}") destroy || true
                let mut cmd = std::process::Command::new("ifconfig");
                cmd.args([name, "destroy"]);
                cmd
            }
        };
        log::debug!("executing: {cmd:?}");
        match cmd.status() {
            Ok(status) => {
                if status.success() {
                    log::debug!("successfully destroyed WireGuard device \"{name}\"");
                } else {
                    log::error!(
                        "can not destry WireGuard device \"{name}\": subprocess exited with code: {code}",
                        code = status
                            .code()
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "unknown exit code".to_string())
                    );
                }
            }
            Err(err) => log::error!("can not destroy WireGuard device \"{name}\": {err}",),
        }
    }
}
impl RunningWireGuardDevice {
    /// create a new `RunningWireGuardDevice`
    pub fn new(name: &str) -> anyhow::Result<Self> {
        #[cfg(target_os = "linux")]
        {
            log::info!("creating a WireGuard interface named \"{name}\"");
            let mut cmd = std::process::Command::new("ip");
            cmd.args(["link", "add", "dev", name, "type", "wireguard"]);
            log::debug!("executing: {cmd:?}");
            match cmd.status() {
                Ok(status) => {
                    if !status.success() {
                        log::warn!(
                            "ignoring that command exited with status {}: {cmd:?}",
                            status
                                .code()
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "unknown exit status".to_string())
                        );
                    }
                }
                Err(err) => {
                    return Err(anyhow!(err)
                        .context(format!("can not create WireGuard interface \"{name}\"")));
                }
            }
        }
        #[cfg(target_os = "freebsd")]
        {
            // load WireGuard kernel module
            log::info!("loading WireGuard kernel module");
            let mut cmd = std::process::Command::new("kldload");
            cmd.args(["-n", "if_wg"]);
            log::debug!("executing: {cmd:?}");
            match cmd.status() {
                Ok(status) => {
                    if !status.success() {
                        bail!(
                            "can not load WireGuard kernel module: process existed with code: {}",
                            status
                                .code()
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "unknown exit status".to_string())
                        )
                    }
                }
                Err(err) => {
                    return Err(anyhow!(err).context("can not load WireGuard kernel module"));
                }
            }

            // create WireGuard interface
            log::info!("creating a WireGuard interface named \"{name}\"");
            let mut cmd = std::process::Command::new("ifconfig");
            cmd.args(["wg", "create", "name", name]);
            log::debug!("executing: {cmd:?}");
            match cmd.status() {
                Ok(status) => {
                    if !status.success() {
                        log::warn!(
                            "ignoring that command exited with status {}: {cmd:?}",
                            status
                                .code()
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "unknown exit status".to_string())
                        );
                    }
                }
                Err(err) => {
                    return Err(anyhow!(err)
                        .context(format!("can not create WireGuard interface \"{name}\"")));
                }
            }
        }

        // return on success
        log::info!("successfully created WireGuard device \"{name}\"");
        Ok(Self {
            device_name: name.to_string(),
        })
    }

    /// enabled the device similar to `ifconfig <DEV> up`
    pub fn up(&self) -> anyhow::Result<()> {
        let name = self.device_name.as_str();
        log::info!("enabling WireGuard device \"{name}\"");
        let mut cmd = {
            #[cfg(target_os = "linux")]
            {
                // ip link set dev $(enquote "${dev}") up
                let mut cmd = std::process::Command::new("ip");
                cmd.args(["link", "set", "dev", name, "up"]);
                cmd
            }
            #[cfg(target_os = "freebsd")]
            {
                // ifconfig $(enquote "${dev}") up
                let mut cmd = std::process::Command::new("ifconfig");
                cmd.args([name, "up"]);
                cmd
            }
        };
        log::debug!("executing: {cmd:?}");
        match cmd.status() {
            Ok(status) => {
                if status.success() {
                    log::debug!("successfully enabled WireGuard device \"{name}\"");
                } else {
                    bail!(
                        "can not enabled WireGuard device \"{name}\": subprocess exited with code: {code}",
                        code = status
                            .code()
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "unknown exit code".to_string())
                    )
                }
            }
            Err(err) => {
                return Err(
                    anyhow!(err).context(format!("can not enabled Wireguard device \"{name}\""))
                );
            }
        }
        Ok(())
    }

    pub fn set_options(&self, options: &DeviceWireguardOptions) -> anyhow::Result<()> {
        let name = self.device_name.as_str();
        log::debug!("setting WireGuard device \"{name}\" options: {options:?}");
        // # Deploy the classic wireguard private key
        // wg set $(enquote "${dev}") private-key $(enquote "${skdir}/wgsk")
        // if test -n "${lport}"; then
        //     frag_append "listen-port $(enquote "$(( lport + 1 ))")"
        // fi

        // ============================== set options via `wg` ==============================
        let mut arguments: Vec<OsString> = Vec::new();
        if let Some(wg_secret_key) = &options.wg_secret_key {
            arguments.push("private-key".into());
            arguments.push(wg_secret_key.get_key_path().into());
        }
        if let Some(wg_listen_port) = &options.wg_listen_port {
            arguments.push("listen-port".into());
            arguments.push(wg_listen_port.to_string().into());
        }
        if let Some(wg_fwmark) = &options.wg_fwmark {
            // TODO: test this
            arguments.push("fwmark".into());
            arguments.push(wg_fwmark.to_string().into());
        }
        let mut cmd = std::process::Command::new("wg");
        for argument in arguments.iter() {
            cmd.arg(argument);
        }
        log::debug!("executing: {cmd:?}");
        match cmd.status() {
            Ok(status) => {
                if status.success() {
                    log::debug!(
                        "successfully set WireGuard device options (via \"wg\" binary) on device \"{name}\""
                    );
                } else {
                    bail!(
                        "can not set WireGuard device \"{name}\" options: subprocess \"wg\" exited with code: {}",
                        status
                            .code()
                            .map(|i| i.to_string())
                            .unwrap_or_else(|| "unknown exit code".to_string())
                    );
                }
            }
            Err(err) => {
                return Err(anyhow!(err).context(format!(
                    "can not set options on WireGuard device \"{name}\""
                )));
            }
        }
        // ============================== set options via `ip` ==============================
        if let Some(set_ip_addr) = &options.set_ip_addr {
            let mut cmd = std::process::Command::new("ip");
            cmd.args([
                "address",
                "add",
                set_ip_addr.to_string().as_str(),
                "dev",
                name,
            ]);
            log::debug!("executing: {cmd:?}");
            match cmd.status() {
                Ok(status) => {
                    if status.success() {
                        log::debug!(
                            "successfully set WireGuard device options (via \"ip\" binary) on device \"{name}\""
                        );
                    } else {
                        bail!(
                            "can not set WireGuard device \"{name}\" options: subprocess \"ip\" exited with code: {}",
                            status
                                .code()
                                .map(|i| i.to_string())
                                .unwrap_or_else(|| "unknown exit code".to_string())
                        );
                    }
                }
                Err(err) => {
                    return Err(anyhow!(err).context(format!(
                        "can not set options on WireGuard device \"{name}\""
                    )));
                }
            }
        }
        Ok(())
    }
}

pub fn read_wg_pubkey(key: &PublicWgKeySource) -> anyhow::Result<PublicSymKey> {
    match &key.inner {
        KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(b64) => {
            decode_wg_pubkey_b64(b64.as_str())
        }
        KeyFromDiskOrB64EncodedStringInner::File(_)
        | KeyFromDiskOrB64EncodedStringInner::Directory(_) => {
            todo!("load WG pubkey from file");
            // key.get_key_path().guaranteed_unwrap()
        }
        #[cfg(feature = "experiment_api")]
        KeyFromDiskOrB64EncodedStringInner::None => {
            todo!("no WireGuard public key set in experimental feature")
        }
    }
}

/// called by [`CliCommand::run`]
pub fn exchange_implementation(
    config: &RosenpassConfig,
    psk_broker_config: Option<BrokerInterface>,
    test_helpers: Option<AppServerTest>,
) -> anyhow::Result<()> {
    // ============================== pre-checks ==============================
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

    // ============================== start WireGuard ==============================
    // this let binding will make sure that all WG devices are destroyed through the `Drop` trait
    let mut running_wireguard_devices: Vec<RunningWireGuardDevice> = Vec::new();

    // create the WG devices
    for device in config.wireguard_devices.iter() {
        match &device.created_by {
            WgDeviceCreateOptions::DoNotCreate => (),
            WgDeviceCreateOptions::Create(options) => {
                let wg_device = RunningWireGuardDevice::new(&device.name)?;
                wg_device.up()?;
                wg_device.set_options(options);

                // move this `wg_device` to the `Vec` so that it lives longer than this for loop
                running_wireguard_devices.push(wg_device);
            }
        }
    }

    // ============================== start rosenpass ==============================
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
                // our_wg_pubkey
                let our_wg_pubkey = wg
                    .our_wireguard_keypair
                    .as_ref()
                    .map(|our| our.get_public_key())
                    .map(|key| read_wg_pubkey(key))
                    .transpose()?;
                // their_wg_pubkey
                // TODO: review the following lines
                let their_wg_pubkey = read_wg_pubkey(&wg.their_wireguard_public_key)?;
                let mut their_wg_pubkey_b64: [u8; _] = [0; 44];
                base64ct::Base64::encode(&their_wg_pubkey, &mut their_wg_pubkey_b64).unwrap();
                let their_wg_pubkey_b64 = String::from_utf8(their_wg_pubkey_b64.to_vec()).unwrap();
                // peer
                let peer_cfg = NativeUnixBrokerConfigBaseBuilder::default()
                    .peer_id_b64(&their_wg_pubkey_b64)?
                    .interface(wg.device_name.clone())
                    .extra_params_ser(&wg.wireguard_options.to_cli_parameters())?
                    .build()
                    .map_err(cfg_err_map)?;
                // broker
                let broker_peer = BrokerPeer::new(broker_store_ptr.clone(), Box::new(peer_cfg));
                // WG key binding
                let wg_key_binding = match (protocol_version, &our_wg_pubkey) {
                    (ProtocolVersion::V03, Some(our_wg_pubkey)) => Some(WireGuardKeyBinding {
                        our_wg_pubkey: *our_wg_pubkey,
                        peer_wg_pubkey: their_wg_pubkey,
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
