use anyhow::Error;
use futures::lock::Mutex;
use std::future::Future;
use std::ops::DerefMut;
use std::pin::Pin;
use std::sync::Arc;
use std::{net::SocketAddr, path::PathBuf, process::Command};

use anyhow::Result;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
use crate::key::WG_B64_LEN;

#[derive(Default)]
pub struct ExchangePeer {
    pub public_keys_dir: PathBuf,
    pub endpoint: Option<SocketAddr>,
    pub persistent_keepalive: Option<u32>,
    pub allowed_ips: Option<String>,
}

#[derive(Default)]
pub struct ExchangeOptions {
    pub verbose: bool,
    pub private_keys_dir: PathBuf,
    pub dev: Option<String>,
    pub ip: Option<String>,
    pub listen: Option<SocketAddr>,
    pub peers: Vec<ExchangePeer>,
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub async fn exchange(_: ExchangeOptions) -> Result<()> {
    use anyhow::anyhow;

    Err(anyhow!(
        "Your system {} is not yet supported. We are happy to receive patches to address this :)",
        std::env::consts::OS
    ))
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod netlink {
    use anyhow::Result;
    use futures_util::{StreamExt as _, TryStreamExt as _};
    use genetlink::GenetlinkHandle;
    use netlink_packet_core::{NLM_F_ACK, NLM_F_REQUEST};
    use netlink_packet_wireguard::nlas::WgDeviceAttrs;
    use rtnetlink::Handle;

    pub async fn link_create_and_up(rtnetlink: &Handle, link_name: String) -> Result<u32> {
        // add the link
        rtnetlink
            .link()
            .add()
            .wireguard(link_name.clone())
            .execute()
            .await?;

        // retrieve the link to be able to up it
        let link = rtnetlink
            .link()
            .get()
            .match_name(link_name.clone())
            .execute()
            .into_stream()
            .into_future()
            .await
            .0
            .unwrap()?;

        // up the link
        rtnetlink
            .link()
            .set(link.header.index)
            .up()
            .execute()
            .await?;

        Ok(link.header.index)
    }

    pub async fn link_cleanup(rtnetlink: &Handle, index: u32) -> Result<()> {
        rtnetlink.link().del(index).execute().await?;

        Ok(())
    }

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
        genetlink: &mut GenetlinkHandle,
        index: u32,
        mut attr: Vec<WgDeviceAttrs>,
    ) -> Result<()> {
        use futures_util::StreamExt as _;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use netlink_packet_generic::GenlMessage;
        use netlink_packet_wireguard::{Wireguard, WireguardCmd};

        // Scope our `set` command to only the device of the specified index
        attr.insert(0, WgDeviceAttrs::IfIndex(index));

        // Construct the WireGuard-specific netlink packet
        let wgc = Wireguard {
            cmd: WireguardCmd::SetDevice,
            nlas: attr,
        };

        // Construct final message
        let genl = GenlMessage::from_payload(wgc);
        let mut nlmsg = NetlinkMessage::from(genl);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

        // Send and wait for the ACK or error
        let (res, _) = genetlink.request(nlmsg).await?.into_future().await;
        if let Some(res) = res {
            let res = res?;
            if let NetlinkPayload::Error(err) = res.payload {
                return Err(err.to_io().into());
            }
        }

        Ok(())
    }
}

#[derive(Clone)]
struct CleanupHandlers(Arc<Mutex<Vec<Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>>>>);

impl CleanupHandlers {
    fn new() -> Self {
        CleanupHandlers(Arc::new(Mutex::new(vec![])))
    }

    async fn enqueue(&self, handler: Pin<Box<dyn Future<Output = Result<(), Error>> + Send>>) {
        self.0.lock().await.push(Box::pin(handler))
    }

    async fn run(self) -> Result<Vec<()>, Error> {
        futures::future::try_join_all(self.0.lock().await.deref_mut()).await
    }
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    use std::fs;

    use anyhow::anyhow;
    use netlink_packet_wireguard::{constants::WG_KEY_LEN, nlas::WgDeviceAttrs};
    use rosenpass::{
        app_server::{AppServer, BrokerPeer},
        config::Verbosity,
        protocol::{SPk, SSk, SymKey},
    };
    use rosenpass_secret_memory::Secret;
    use rosenpass_util::file::{LoadValue as _, LoadValueB64};
    use rosenpass_wireguard_broker::brokers::native_unix::{
        NativeUnixBroker, NativeUnixBrokerConfigBaseBuilder, NativeUnixBrokerConfigBaseBuilderError,
    };

    let (connection, rtnetlink, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let link_name = options.dev.clone().unwrap_or("rosenpass0".to_string());
    let link_index = netlink::link_create_and_up(&rtnetlink, link_name.clone()).await?;

    let cleanup_handlers = CleanupHandlers::new();
    let final_cleanup_handlers = (&cleanup_handlers).clone();

    cleanup_handlers
        .enqueue(Box::pin(async move {
            netlink::link_cleanup_standalone(link_index).await
        }))
        .await;

    ctrlc_async::set_async_handler(async move {
        final_cleanup_handlers
            .run()
            .await
            .expect("Failed to clean up");
    })?;

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

    // Deploy the classic wireguard private key
    let (connection, mut genetlink, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let wgsk_path = options.private_keys_dir.join("wgsk");

    let wgsk = Secret::<WG_KEY_LEN>::load_b64::<WG_B64_LEN, _>(wgsk_path)?;

    let mut attr: Vec<WgDeviceAttrs> = Vec::with_capacity(2);
    attr.push(WgDeviceAttrs::PrivateKey(*wgsk.secret()));

    if let Some(listen) = options.listen {
        if listen.port() == u16::MAX {
            return Err(anyhow!("You may not use {} as the listen port.", u16::MAX));
        }

        attr.push(WgDeviceAttrs::ListenPort(listen.port() + 1));
    }

    netlink::wg_set(&mut genetlink, link_index, attr).await?;

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
            .peer_id_b64(&fs::read_to_string(wgpk)?)?
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
        )?;

        // Configure routes
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

    netlink::link_cleanup(&rtnetlink, link_index).await?;

    match out {
        Ok(_) => Ok(()),
        Err(e) => {
            // Check if the returned error is actually EINTR, in which case, the run actually succeeded.
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
