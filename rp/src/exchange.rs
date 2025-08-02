use std::any::type_name;
use std::{borrow::Borrow, net::SocketAddr, path::PathBuf};

use tokio::process::Command;

use anyhow::{bail, ensure, Context, Result};
use futures_util::TryStreamExt as _;
use serde::Deserialize;

use rosenpass::config::ProtocolVersion;
use rosenpass::{
    app_server::{AppServer, BrokerPeer},
    config::Verbosity,
    protocol::{
        basic_types::{SPk, SSk, SymKey},
        osk_domain_separator::OskDomainSeparator,
    },
};
use rosenpass_secret_memory::Secret;
use rosenpass_util::file::{LoadValue as _, LoadValueB64};
use rosenpass_util::functional::{ApplyExt, MutatingExt};
use rosenpass_util::result::OkExt;
use rosenpass_util::tokio::janitor::{spawn_cleanup_job, try_spawn_daemon};
use rosenpass_wireguard_broker::brokers::native_unix::{
    NativeUnixBroker, NativeUnixBrokerConfigBaseBuilder,
};
use tokio::task::spawn_blocking;

use crate::key::WG_B64_LEN;

/// Extra-special measure to structure imports from the various
/// netlink related crates used in [super]
mod netlink {
    /// Re-exports from [::netlink_packet_core]
    pub mod core {
        pub use ::netlink_packet_core::{NetlinkMessage, NLM_F_ACK, NLM_F_REQUEST};
    }

    /// Re-exports from [::rtnetlink]
    pub mod rtnl {
        pub use ::rtnetlink::Error;
        pub use ::rtnetlink::Handle;
    }

    /// Re-exports from [::genetlink] and [::netlink_packet_generic]
    pub mod genl {
        pub use ::genetlink::GenetlinkHandle as Handle;
        pub use ::netlink_packet_generic::GenlMessage as Message;
    }

    /// Re-exports from [::netlink_packet_wireguard]
    pub mod wg {
        pub use ::netlink_packet_wireguard::constants::WG_KEY_LEN as KEY_LEN;
        pub use ::netlink_packet_wireguard::nlas::WgDeviceAttrs as DeviceAttrs;
        pub use ::netlink_packet_wireguard::{Wireguard, WireguardCmd};
    }
}

type WgSecretKey = Secret<{ netlink::wg::KEY_LEN }>;

/// Used to define a peer for the rosenpass connection that consists of
/// a directory for storing public keys and optionally an IP address and port of the endpoint,
/// for how long the connection should be kept alive and a list of allowed IPs for the peer.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangePeer {
    /// Directory where public keys are stored
    pub public_keys_dir: PathBuf,
    /// The IP address of the endpoint
    pub endpoint: Option<SocketAddr>,
    /// For how long to keep the connection alive
    pub persistent_keepalive: Option<u32>,
    /// The IPs that are allowed for this peer.
    pub allowed_ips: Option<String>,
    /// The protocol version used by the peer.
    #[serde(default)]
    pub protocol_version: ProtocolVersion,
}

/// Options for the exchange operation of the `rp` binary.
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExchangeOptions {
    /// Whether the cli output should be verbose.
    pub verbose: bool,
    /// path to the directory where private keys are stored.
    pub private_keys_dir: PathBuf,
    /// The link rosenpass should run as. If None is given [exchange] will use `"rosenpass0"`
    /// instead.
    pub dev: Option<String>,
    /// The IP-address rosenpass should run under.
    pub ip: Option<String>,
    /// The IP-address and port that the rosenpass [AppServer](rosenpass::app_server::AppServer)
    /// should use.
    pub listen: Option<SocketAddr>,
    /// Other peers a connection should be initialized to
    pub peers: Vec<ExchangePeer>,
}

/// Manage the lifetime of WireGuard devices uses for rp
#[derive(Debug, Default)]
struct WireGuardDeviceImpl {
    // TODO: Can we merge these two somehow?
    rtnl_netlink_handle_cache: Option<netlink::rtnl::Handle>,
    genl_netlink_handle_cache: Option<netlink::genl::Handle>,
    /// Handle and name of the device
    device: Option<(u32, String)>,
}

impl WireGuardDeviceImpl {
    fn take(&mut self) -> WireGuardDeviceImpl {
        Self::default().mutating(|nu| std::mem::swap(self, nu))
    }

    async fn open(&mut self, device_name: String) -> anyhow::Result<()> {
        let mut rtnl_link = self.rtnl_netlink_handle()?.link();
        let device_name_ref = &device_name;

        // Make sure that there is no device called `device_name` before we start
        rtnl_link
            .get()
            .match_name(device_name.to_owned())
            .execute()
            // Count the number of occurences
            .try_fold(0, |acc, _val| async move {
                Ok(acc + 1)
            }).await
            // Extract the error's raw system error code
            .map_err(|e| {
                use netlink::rtnl::Error as E;
                match e {
                    E::NetlinkError(msg) => {
                        let raw_code = -msg.raw_code();
                        (E::NetlinkError(msg), Some(raw_code))
                    },
                    _ => (e, None),
                }
            })
            .apply(|r| {
                match r {
                    // No such device, which is exactly what we are expecting
                    Ok(0) | Err((_, Some(libc::ENODEV))) => Ok(()),
                    // Device already exists
                    Ok(_) => bail!("\
                        Trying to create a network device for Rosenpass under the name \"{device_name}\", \
                        but at least one device under the name aready exists."),
                    // Other error
                    Err((e, _)) => bail!(e),
                }
            })?;

        // Add the link, equivalent to `ip link add <link_name> type wireguard`.
        rtnl_link
            .add()
            .wireguard(device_name.to_owned())
            .execute()
            .await?;
        log::info!("Created network device!");

        // Retrieve a handle for the newly created device
        let device_handle = rtnl_link
            .get()
            .match_name(device_name.to_owned())
            .execute()
            .err_into::<anyhow::Error>()
            .try_fold(Option::None, |acc, val| async move {
                ensure!(acc.is_none(), "\
                    Created a network device for Rosenpass under the name \"{device_name_ref}\", \
                    but upon trying to determine the handle for the device using named-based lookup, we received multiple handles. \
                    We checked beforehand whether the device already exists. \
                    This should not happen. Unsure how to proceed. Terminating.");
                Ok(Some(val))
            }).await?
            .with_context(|| format!("\
                Created a network device for Rosenpass under the name \"{device_name}\", \
                but upon trying to determine the handle for the device using named-based lookup, we received no handle. \
                This should not happen. Unsure how to proceed. Terminating."))?
            .apply(|msg| msg.header.index);

        // Now we can actually start to mark the device as initialized.
        // Note that if the handle retrieval above does not work, the destructor
        // will not run and the device will not be erased.
        // This is, for now, the desired behavior as we need the handle to erase
        // the device anyway.
        self.device = Some((device_handle, device_name));

        // Activate the link, equivalent to `ip link set dev <DEV> up`.
        rtnl_link.set(device_handle).up().execute().await?;

        Ok(())
    }

    async fn close(mut self) {
        // Check if the device is properly initialized and retrieve the device info
        let (device_handle, device_name) = match self.device.take() {
            Some(val) => val,
            // Nothing to do, not yet properly initialized
            None => return,
        };

        // Erase the network device; the rest of the function is just error handling
        let res = async move {
            self.rtnl_netlink_handle()?
                .link()
                .del(device_handle)
                .execute()
                .await?;
            log::debug!("Erased network interface!");
            anyhow::Ok(())
        }
        .await;

        // Here we test if the error needs printing at all
        let res = 'do_print: {
            // Short-circuit if the deletion was successful
            let err = match res {
                Ok(()) => break 'do_print Ok(()),
                Err(err) => err,
            };

            // Extract the rtnetlink error, so we can inspect it
            let err = match err.downcast::<netlink::rtnl::Error>() {
                Ok(rtnl_err) => rtnl_err,
                Err(other_err) => break 'do_print Err(other_err),
            };

            // TODO: This is a bit brittle, as the rtnetlink error enum looks like
            //       E::NetlinkError is a sort of "unknown error" case. If they explicitly
            //       add support for the "no such device" errors or other ones we check for in
            //       this block, then this code may no longer filter these errors
            // Extract the raw netlink error code
            use netlink::rtnl::Error as E;
            let error_code = match err {
                E::NetlinkError(ref msg) => -msg.raw_code(),
                err => break 'do_print Err(err.into()),
            };

            // Check whether its just the "no such device" error
            #[allow(clippy::single_match)]
            match error_code {
                libc::ENODEV => break 'do_print Ok(()),
                _ => {}
            }

            // Otherwise, we just print the error
            Err(err.into())
        };

        if let Err(err) = res {
            log::warn!("Could not remove network device `{device_name}`: {err:?}");
        }
    }

    pub async fn add_ip_address(&self, addr: &str) -> anyhow::Result<()> {
        // TODO: Migrate to using netlink
        Command::new("ip")
            .args(["address", "add", addr, "dev", self.name()?])
            .status()
            .await?;
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.device.is_some()
    }

    pub fn maybe_name(&self) -> Option<&str> {
        self.device.as_ref().map(|slot| slot.1.borrow())
    }

    /// Return the raw handle for this device
    pub fn maybe_raw_handle(&self) -> Option<u32> {
        self.device.as_ref().map(|slot| slot.0)
    }

    pub fn name(&self) -> anyhow::Result<&str> {
        self.maybe_name()
            .with_context(|| format!("{} has not been initialized!", type_name::<Self>()))
    }

    /// Return the raw handle for this device
    pub fn raw_handle(&self) -> anyhow::Result<u32> {
        self.maybe_raw_handle()
            .with_context(|| format!("{} has not been initialized!", type_name::<Self>()))
    }

    pub async fn set_private_key_and_listen_addr(
        &mut self,
        wgsk: &WgSecretKey,
        listen_port: Option<u16>,
    ) -> anyhow::Result<()> {
        use netlink as nl;

        // The attributes to set
        // TODO: This exposes the secret key; we should probably run this in a separate process
        //       or on a separate stack and have zeroizing allocator globally.
        let mut attrs = vec![
            nl::wg::DeviceAttrs::IfIndex(self.raw_handle()?),
            nl::wg::DeviceAttrs::PrivateKey(*wgsk.secret()),
        ];

        // Optional listen port for WireGuard
        if let Some(port) = listen_port {
            attrs.push(nl::wg::DeviceAttrs::ListenPort(port));
        }

        // The netlink request we are trying to send
        let req = nl::wg::Wireguard {
            cmd: nl::wg::WireguardCmd::SetDevice,
            nlas: attrs,
        };

        // Boilerplate; wrap the request into more structures
        let req = req
            .apply(nl::genl::Message::from_payload)
            .apply(nl::core::NetlinkMessage::from)
            .mutating(|req| {
                req.header.flags = nl::core::NLM_F_REQUEST | nl::core::NLM_F_ACK;
            });

        // Send the request
        self.genl_netlink_handle()?
            .request(req)
            .await?
            // Collect all errors (let try_fold do all the work)
            .try_fold((), |_, _| async move { Ok(()) })
            .await?;

        Ok(())
    }

    fn take_rtnl_netlink_handle(&mut self) -> Result<netlink::rtnl::Handle> {
        if let Some(handle) = self.rtnl_netlink_handle_cache.take() {
            Ok(handle)
        } else {
            let (connection, handle, _) = rtnetlink::new_connection()?;

            // Making sure that the connection has a chance to terminate before the
            // application exits
            try_spawn_daemon(async move {
                connection.await;
                Ok(())
            })?;

            Ok(handle)
        }
    }

    fn rtnl_netlink_handle(&mut self) -> Result<&mut netlink::rtnl::Handle> {
        let netlink_handle = self.take_rtnl_netlink_handle()?;
        self.rtnl_netlink_handle_cache.insert(netlink_handle).ok()
    }

    fn take_genl_netlink_handle(&mut self) -> Result<netlink::genl::Handle> {
        if let Some(handle) = self.genl_netlink_handle_cache.take() {
            Ok(handle)
        } else {
            let (connection, handle, _) = genetlink::new_connection()?;

            // Making sure that the connection has a chance to terminate before the
            // application exits
            try_spawn_daemon(async move {
                connection.await;
                Ok(())
            })?;

            Ok(handle)
        }
    }

    fn genl_netlink_handle(&mut self) -> Result<&mut netlink::genl::Handle> {
        let netlink_handle = self.take_genl_netlink_handle()?;
        self.genl_netlink_handle_cache.insert(netlink_handle).ok()
    }
}

struct WireGuardDevice {
    _impl: WireGuardDeviceImpl,
}

impl WireGuardDevice {
    /// Creates a netlink named `link_name` and changes the state to up. It returns the index
    /// of the interface in the list of interfaces as the result or an error if any of the
    /// operations of creating the link or changing its state to up fails.
    pub async fn create_device(device_name: String) -> Result<Self> {
        let mut _impl = WireGuardDeviceImpl::default();
        _impl.open(device_name).await?;
        assert!(_impl.is_open()); // Sanity check
        Ok(WireGuardDevice { _impl })
    }

    pub fn name(&self) -> &str {
        self._impl.name().unwrap()
    }

    /// Return the raw handle for this device
    #[allow(dead_code)]
    pub fn raw_handle(&self) -> u32 {
        self._impl.raw_handle().unwrap()
    }

    pub async fn add_ip_address(&self, addr: &str) -> anyhow::Result<()> {
        self._impl.add_ip_address(addr).await
    }

    pub async fn set_private_key_and_listen_addr(
        &mut self,
        wgsk: &WgSecretKey,
        listen_port: Option<u16>,
    ) -> anyhow::Result<()> {
        self._impl
            .set_private_key_and_listen_addr(wgsk, listen_port)
            .await
    }
}

impl Drop for WireGuardDevice {
    fn drop(&mut self) {
        let _impl = self._impl.take();
        spawn_cleanup_job(async move {
            _impl.close().await;
            Ok(())
        });
    }
}

/// Sets up the rosenpass link and wireguard and configures both with the configuration specified by
/// `options`.
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    // Load the server parameter files
    // TODO: Should be async, but right now its now
    let wgsk = options
        .private_keys_dir
        .join("wgsk")
        .apply(WgSecretKey::load_b64::<WG_B64_LEN, _>)?;
    let rpsk = options.private_keys_dir.join("pqsk").apply(SSk::load)?;
    let rppk = options.private_keys_dir.join("pqpk").apply(SPk::load)?;

    // Setup the WireGuard device
    let device = options.dev.as_deref().unwrap_or("rosenpass0");
    let mut device = WireGuardDevice::create_device(device.to_owned()).await?;

    // Assign WG secret key & port
    device
        .set_private_key_and_listen_addr(&wgsk, options.listen.map(|ip| ip.port() + 1))
        .await?;
    std::mem::drop(wgsk);

    // Assign the public IP address for the interface
    if let Some(ref ip) = options.ip {
        device.add_ip_address(ip).await?;
    }

    let mut srv = Box::new(AppServer::new(
        Some((rpsk, rppk)),
        Vec::from_iter(options.listen),
        match options.verbose {
            true => Verbosity::Verbose,
            false => Verbosity::Quiet,
        },
        None,
    )?);

    let broker_store_ptr = srv.register_broker(Box::new(NativeUnixBroker::new()))?;

    // Configure everything per peer.
    for peer in options.peers {
        // TODO: Some of this is sync but should be async
        let wgpk = peer
            .public_keys_dir
            .join("wgpk")
            .apply(tokio::fs::read_to_string)
            .await?;
        let pqpk = peer.public_keys_dir.join("pqpk").apply(SPk::load)?;
        let psk = peer.public_keys_dir.join("psk");
        let psk = psk
            .exists()
            .then(|| SymKey::load_b64::<WG_B64_LEN, _>(psk))
            .transpose()?;

        let mut extra_params: Vec<String> = Vec::with_capacity(6);
        if let Some(endpoint) = peer.endpoint {
            extra_params.push("endpoint".to_string());

            // Peer endpoints always use (port + 1) in wg set params
            let endpoint = SocketAddr::new(endpoint.ip(), endpoint.port() + 1);
            extra_params.push(endpoint.to_string());
        }
        if let Some(persistent_keepalive) = peer.persistent_keepalive {
            extra_params.push("persistent-keepalive".to_string());
            extra_params.push(persistent_keepalive.to_string());
        }
        if let Some(allowed_ips) = &peer.allowed_ips {
            extra_params.push("allowed-ips".to_string());
            extra_params.push(allowed_ips.clone());
        }

        let peer_cfg = NativeUnixBrokerConfigBaseBuilder::default()
            .peer_id_b64(&wgpk)?
            .interface(device.name().to_owned())
            .extra_params_ser(&extra_params)?
            .build()
            .with_context(|| format!("Could not configure broker to supply keys from Rosenpass to WireGuard for peer {wgpk}."))?;

        let broker_peer = Some(BrokerPeer::new(
            broker_store_ptr.clone(),
            Box::new(peer_cfg),
        ));

        srv.add_peer(
            psk,
            pqpk,
            None,
            broker_peer,
            peer.endpoint.map(|x| x.to_string()),
            peer.protocol_version,
            OskDomainSeparator::for_wireguard_psk(),
        )?;

        // Configure routes, equivalent to `ip route replace <allowed_ips> dev <dev>` and set up
        // the cleanup as `ip route del <allowed_ips>`.
        if let Some(allowed_ips) = peer.allowed_ips {
            Command::new("ip")
                .args(["route", "replace", &allowed_ips, "dev", device.name()])
                .status()
                .await
                .with_context(|| format!("Could not configure routes for peer {wgpk}"))?;
        }
    }

    log::info!("Starting to perform rosenpass key exchanges!");
    spawn_blocking(move || srv.event_loop()).await?
}
