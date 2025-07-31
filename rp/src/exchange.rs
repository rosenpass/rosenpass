use std::{
    future::Future, net::SocketAddr, ops::DerefMut, path::PathBuf, pin::Pin, process::Command,
    sync::Arc,
};

use anyhow::{anyhow, bail, ensure, Context, Error, Result};
use futures_util::{StreamExt as _, TryStreamExt as _};
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
use rosenpass_util::functional::ApplyExt;
use rosenpass_wireguard_broker::brokers::native_unix::{
    NativeUnixBroker, NativeUnixBrokerConfigBaseBuilder, NativeUnixBrokerConfigBaseBuilderError,
};

use crate::key::WG_B64_LEN;

/// Extra-special measure to structure imports from the various
/// netlink related crates used in [super]
mod netlink {
    /// Re-exports from [::netlink_packet_core]
    pub mod core {
        pub use ::netlink_packet_core::{NetlinkMessage, NetlinkPayload, NLM_F_ACK, NLM_F_REQUEST};
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

/// Creates a netlink named `link_name` and changes the state to up. It returns the index
/// of the interface in the list of interfaces as the result or an error if any of the
/// operations of creating the link or changing its state to up fails.
pub async fn link_create_and_up(
    rtnetlink: &netlink::rtnl::Handle,
    device_name: &str,
) -> Result<u32> {
    let mut rtnl_link = rtnetlink.link();

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

    // Retrieve a handle for the newly created device
    let dev = rtnl_link
        .get()
        .match_name(device_name.to_owned())
        .execute()
        .err_into::<anyhow::Error>()
        .try_fold(Option::None, |acc, val| async move {
            ensure!(acc.is_none(), "\
                Created a network device for Rosenpass under the name \"{device_name}\", \
                but upon trying to determine the handle for the device using named-based lookup, we received multiple handles. \
                We checked beforehand whether the device already exists. \
                This should not happen. Unsure how to proceed. Terminating.");
            Ok(Some(val))
        }).await?
        .with_context(|| format!("\
            Created a network device for Rosenpass under the name \"{device_name}\", \
            but upon trying to determine the handle for the device using named-based lookup, we received no handle. \
            This should not happen. Unsure how to proceed. Terminating."))?;

    // Activate the link, equivalent to `ip link set dev <DEV> up`.
    rtnl_link.set(dev.header.index).up().execute().await?;

    Ok(dev.header.index)
}

/// Deletes a link using rtnetlink. The link is specified using its index in the list of links.
pub async fn link_cleanup(rtnetlink: &netlink::rtnl::Handle, index: u32) -> Result<()> {
    rtnetlink.link().del(index).execute().await?;

    Ok(())
}

/// Deletes a link using rtnetlink. The link is specified using its index in the list of links.
/// In contrast to [link_cleanup], this function create a new socket connection to netlink and
/// *ignores errors* that occur during deletion.
pub async fn link_cleanup_standalone(index: u32) -> Result<()> {
    let (connection, rtnetlink, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    // We don't care if this fails, as the device may already have been auto-cleaned up.
    let _ = rtnetlink.link().del(index).execute().await;

    Ok(())
}

/// This replicates the functionality of the `wg set` command line tool.
///
/// It sets the specified WireGuard attributes of the indexed device by
/// communicating with WireGuard's generic netlink interface, like the
/// `wg` tool does.
pub async fn wg_set(
    genetlink: &mut netlink::genl::Handle,
    index: u32,
    mut attr: Vec<netlink::wg::DeviceAttrs>,
) -> Result<()> {
    use netlink as nl;

    // Scope our `set` command to only the device of the specified index.
    attr.insert(0, nl::wg::DeviceAttrs::IfIndex(index));

    // Construct the WireGuard-specific netlink packet
    let wgc = nl::wg::Wireguard {
        cmd: nl::wg::WireguardCmd::SetDevice,
        nlas: attr,
    };

    // Construct final message.
    let genl = nl::genl::Message::from_payload(wgc);
    let mut nlmsg = nl::core::NetlinkMessage::from(genl);
    nlmsg.header.flags = nl::core::NLM_F_REQUEST | nl::core::NLM_F_ACK;

    // Send and wait for the ACK or error.
    let (res, _) = genetlink.request(nlmsg).await?.into_future().await;
    if let Some(res) = res {
        let res = res?;
        if let nl::core::NetlinkPayload::Error(err) = res.payload {
            return Err(err.to_io().into());
        }
    }

    Ok(())
}

/// A wrapper for a list of cleanup handlers that can be used in an asynchronous context
/// to clean up after the usage of rosenpass or if the `rp` binary is interrupted with ctrl+c
/// or a `SIGINT` signal in general.
#[derive(Clone)]
struct CleanupHandlers(
    Arc<::futures::lock::Mutex<Vec<Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>>>>,
);

impl CleanupHandlers {
    /// Creates a new list of [CleanupHandlers].
    fn new() -> Self {
        CleanupHandlers(Arc::new(::futures::lock::Mutex::new(vec![])))
    }

    /// Enqueues a new cleanup handler in the form of a [Future].
    async fn enqueue(&self, handler: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>) {
        self.0.lock().await.push(Box::pin(handler))
    }

    /// Runs all cleanup handlers. Following the documentation of [futures::future::try_join_all]:
    /// If any cleanup handler returns an error then all other cleanup handlers will be canceled and
    /// an error will be returned immediately. If all cleanup handlers complete successfully,
    /// however, then the returned future will succeed with a Vec of all the successful results.
    async fn run(self) -> Result<Vec<()>, Error> {
        futures::future::try_join_all(self.0.lock().await.deref_mut()).await
    }
}

/// Sets up the rosenpass link and wireguard and configures both with the configuration specified by
/// `options`.
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    let (connection, rtnetlink, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let link_name = options.dev.clone().unwrap_or("rosenpass0".to_string());
    let link_index = link_create_and_up(&rtnetlink, &link_name).await?;

    // Set up a list of (initiallc empty) cleanup handlers that are to be run if
    // ctrl-c is hit or generally a `SIGINT` signal is received and always in the end.
    let cleanup_handlers = CleanupHandlers::new();
    let final_cleanup_handlers = cleanup_handlers.clone();

    cleanup_handlers
        .enqueue(Box::pin(async move {
            link_cleanup_standalone(link_index).await
        }))
        .await;

    ctrlc_async::set_async_handler(async move {
        final_cleanup_handlers
            .run()
            .await
            .expect("Failed to clean up");
    })?;

    // Run `ip address add <ip> dev <dev>` and enqueue `ip address del <ip> dev <dev>` as a cleanup.
    if let Some(ip) = options.ip {
        let dev = options.dev.clone().unwrap_or("rosenpass0".to_string());
        Command::new("ip")
            .arg("address")
            .arg("add")
            .arg(ip.clone())
            .arg("dev")
            .arg(dev.clone())
            .status()
            .expect("failed to configure ip");
        cleanup_handlers
            .enqueue(Box::pin(async move {
                Command::new("ip")
                    .arg("address")
                    .arg("del")
                    .arg(ip)
                    .arg("dev")
                    .arg(dev)
                    .status()
                    .expect("failed to remove ip");
                Ok(())
            }))
            .await;
    }

    // Deploy the classic wireguard private key.
    let (connection, mut genetlink, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let wgsk_path = options.private_keys_dir.join("wgsk");

    let wgsk = Secret::<{ netlink::wg::KEY_LEN }>::load_b64::<WG_B64_LEN, _>(wgsk_path)?;

    let mut attr: Vec<netlink::wg::DeviceAttrs> = Vec::with_capacity(2);
    attr.push(netlink::wg::DeviceAttrs::PrivateKey(*wgsk.secret()));

    if let Some(listen) = options.listen {
        if listen.port() == u16::MAX {
            return Err(anyhow!("You may not use {} as the listen port.", u16::MAX));
        }

        attr.push(netlink::wg::DeviceAttrs::ListenPort(listen.port() + 1));
    }

    wg_set(&mut genetlink, link_index, attr).await?;

    // set up the rosenpass AppServer
    let pqsk = options.private_keys_dir.join("pqsk");
    let pqpk = options.private_keys_dir.join("pqpk");

    let sk = SSk::load(&pqsk)?;
    let pk = SPk::load(&pqpk)?;

    let mut srv = Box::new(AppServer::new(
        Some((sk, pk)),
        if let Some(listen) = options.listen {
            vec![listen]
        } else {
            Vec::with_capacity(0)
        },
        if options.verbose {
            Verbosity::Verbose
        } else {
            Verbosity::Quiet
        },
        None,
    )?);

    let broker_store_ptr = srv.register_broker(Box::new(NativeUnixBroker::new()))?;

    fn cfg_err_map(e: NativeUnixBrokerConfigBaseBuilderError) -> anyhow::Error {
        anyhow::Error::msg(format!("NativeUnixBrokerConfigBaseBuilderError: {:?}", e))
    }

    // Configure everything per peer.
    for peer in options.peers {
        let wgpk = peer.public_keys_dir.join("wgpk");
        let pqpk = peer.public_keys_dir.join("pqpk");
        let psk = peer.public_keys_dir.join("psk");

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
            .peer_id_b64(&std::fs::read_to_string(wgpk)?)?
            .interface(link_name.clone())
            .extra_params_ser(&extra_params)?
            .build()
            .map_err(cfg_err_map)?;

        let broker_peer = Some(BrokerPeer::new(
            broker_store_ptr.clone(),
            Box::new(peer_cfg),
        ));

        srv.add_peer(
            if psk.exists() {
                Some(SymKey::load_b64::<WG_B64_LEN, _>(psk))
            } else {
                None
            }
            .transpose()?,
            SPk::load(&pqpk)?,
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
                .arg("route")
                .arg("replace")
                .arg(allowed_ips.clone())
                .arg("dev")
                .arg(options.dev.clone().unwrap_or("rosenpass0".to_string()))
                .status()
                .expect("failed to configure route");
            cleanup_handlers
                .enqueue(Box::pin(async move {
                    Command::new("ip")
                        .arg("route")
                        .arg("del")
                        .arg(allowed_ips)
                        .status()
                        .expect("failed to remove ip");
                    Ok(())
                }))
                .await;
        }
    }

    let out = srv.event_loop();

    link_cleanup(&rtnetlink, link_index).await?;

    match out {
        Ok(_) => Ok(()),
        Err(e) => {
            // Check if the returned error is actually EINTR, in which case, the run actually
            // succeeded.
            let is_ok = if let Some(e) = e.root_cause().downcast_ref::<std::io::Error>() {
                matches!(e.kind(), std::io::ErrorKind::Interrupted)
            } else {
                false
            };

            if is_ok {
                Ok(())
            } else {
                Err(e)
            }
        }
    }
}
