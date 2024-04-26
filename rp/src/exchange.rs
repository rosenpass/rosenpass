use std::{cell::RefCell, net::SocketAddr, path::PathBuf, rc::Rc};

use anyhow::{anyhow, Result};
use ipnet::IpNet;
use rosenpass::app_server::WgPeerAdapter;
use wireguard_nt::SetPeer;

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
    pub listen: Option<SocketAddr>,
    pub peers: Vec<ExchangePeer>,
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "windows")))]
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

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    use std::fs;

    use anyhow::anyhow;
    use netlink_packet_wireguard::{constants::WG_KEY_LEN, nlas::WgDeviceAttrs};
    use rosenpass::{
        app_server::{AppServer, UnixWireguardOut},
        config::Verbosity,
        protocol::{SPk, SSk, SymKey},
    };
    use rosenpass_secret_memory::Secret;
    use rosenpass_util::file::{LoadValue as _, LoadValueB64};

    let (connection, rtnetlink, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let link_name = options.dev.unwrap_or("rosenpass0".to_string());
    let link_index = netlink::link_create_and_up(&rtnetlink, link_name.clone()).await?;

    ctrlc_async::set_async_handler(async move {
        netlink::link_cleanup_standalone(link_index)
            .await
            .expect("Failed to clean up");
    })?;

    // Deploy the classic wireguard private key
    let (connection, mut genetlink, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let wgsk_path = options.private_keys_dir.join("wgsk");

    let wgsk = Secret::<WG_KEY_LEN>::load_b64(wgsk_path)?;

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
        sk,
        pk,
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

        srv.add_peer(
            if psk.exists() {
                Some(SymKey::load_b64(psk))
            } else {
                None
            }
            .transpose()?,
            SPk::load(&pqpk)?,
            None,
            Some(UnixWireguardOut {
                dev: link_name.clone(),
                pk: fs::read_to_string(wgpk)?,
                extra_params,
            }),
            peer.endpoint.map(|x| x.to_string()),
        )?;
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

#[cfg(target_os = "windows")]
struct WindowsWireguardOut {
    adapter: Rc<RefCell<wireguard_nt::Adapter>>,
    peer: wireguard_nt::SetPeer,
    adapter_ip: IpNet,
}

#[cfg(target_os = "windows")]
impl WindowsWireguardOut {
    fn new(
        adapter: Rc<RefCell<wireguard_nt::Adapter>>,
        adapter_ip: IpNet,
        peer: wireguard_nt::SetPeer,
    ) -> anyhow::Result<Self> {
        let wgout = WindowsWireguardOut {
            adapter,
            adapter_ip,
            peer,
        };

        let config = wgout.adapter.borrow_mut().get_config();

        let mut peers: Vec<wireguard_nt::SetPeer> = config
            .peers
            .iter()
            .filter_map(|p| {
                //Duplicate entry
                if p.endpoint == wgout.peer.endpoint
                    && Some(p.public_key) == wgout.peer.public_key
                    && p.allowed_ips == wgout.peer.allowed_ips
                {
                    None
                } else {
                    Some(SetPeer {
                        preshared_key: Some(p.preshared_key),
                        public_key: Some(p.public_key),
                        keep_alive: Some(p.persistent_keepalive),
                        allowed_ips: p.allowed_ips.clone(),
                        endpoint: p.endpoint,
                    })
                }
            })
            .collect();

        peers.push(wgout.peer.clone());

        let config = wireguard_nt::SetInterface {
            //Wireguard listen port is one added
            listen_port: Some(config.listen_port + 1),
            public_key: Some(config.public_key),
            private_key: Some(config.private_key),
            peers,
        };

        wgout.adapter.borrow_mut().down();

        wgout
            .adapter
            .borrow_mut()
            .set_config(&config)
            .map_err(|err| anyhow!("Error setting adapter config {}", err))?;

        wgout
            .adapter
            .borrow_mut()
            .set_default_route(&[wgout.adapter_ip.clone()], &config)
            .map_err(|err| anyhow!("Error setting adapter default route {}", err))?;
        wgout.adapter.borrow_mut().up();

        Ok(wgout)
    }
}

#[cfg(target_os = "windows")]
impl WgPeerAdapter for WindowsWireguardOut {
    fn update_wg_psk(&mut self, key: &rosenpass_secret_memory::Secret<32>) -> anyhow::Result<()> {
        let config = self.adapter.borrow_mut().get_config();

        let mut peer_found = false;
        let peers: Vec<wireguard_nt::SetPeer> = config
            .peers
            .iter()
            .map(|p| {
                let mut peer = SetPeer {
                    preshared_key: Some(p.preshared_key),
                    public_key: Some(p.public_key),
                    keep_alive: Some(p.persistent_keepalive),
                    allowed_ips: p.allowed_ips.clone(),
                    endpoint: p.endpoint,
                };

                if p.endpoint == self.peer.endpoint
                    && Some(p.public_key) == self.peer.public_key
                    && p.allowed_ips == self.peer.allowed_ips
                {
                    peer_found = true;
                    peer.preshared_key = Some(key.secret().clone());
                }
                peer
            })
            .collect();

        if !peer_found {
            return Err(anyhow!("Peer not found"));
        }

        let config = wireguard_nt::SetInterface {
            listen_port: Some(config.listen_port),
            public_key: Some(config.public_key),
            private_key: Some(config.private_key),
            peers,
        };

        self.adapter.borrow_mut().down();

        self.adapter
            .borrow_mut()
            .set_config(&config)
            .map_err(|err| anyhow!("Error setting adapter config {}", err))?;

        self.adapter
            .borrow_mut()
            .set_default_route(&[self.adapter_ip.clone()], &config)
            .map_err(|err| anyhow!("Error setting adapter default route {}", err))?;

        self.adapter.borrow_mut().up();

        Ok(())
    }
}

#[cfg(target_os = "windows")]
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    use std::str::FromStr;

    use anyhow::bail;
    use base64::Engine;
    use rosenpass::{
        app_server::AppServer,
        config::Verbosity,
        protocol::{SPk, SSk, SymKey},
    };
    use rosenpass_secret_memory::Secret;
    use rosenpass_util::file::{LoadValue as _, LoadValueB64};
    use zeroize::Zeroize;

    let wireguard = unsafe { wireguard_nt::load_from_path("wireguard-nt/bin/amd64/wireguard.dll") }
        .expect("Failed to load wireguard dll");

    let adapter = match wireguard_nt::Adapter::open(wireguard.clone(), "rosenpass") {
        Ok(_) => {
            bail!("Existing adapter already configured");
        }
        Err(_) => match wireguard_nt::Adapter::create(wireguard, "WireGuard", "Rosenpass", None) {
            Ok(a) => a,
            Err(_) => {
                bail!("Error creating adapter");
            }
        },
    };

    let wgsk_path = options.private_keys_dir.join("wgsk");

    let wgsk = Secret::<32>::load_b64(wgsk_path)?;

    if let Some(listen) = options.listen {
        if listen.port() == u16::MAX {
            return Err(anyhow!("You may not use {} as the listen port.", u16::MAX));
        }
    }

    let pqsk = options.private_keys_dir.join("pqsk");
    let pqpk = options.private_keys_dir.join("pqpk");

    let sk = SSk::load(&pqsk)?;
    let pk = SPk::load(&pqpk)?;

    let mut wg_private_key = [0u8; 32];
    wg_private_key.copy_from_slice(wgsk.secret());

    let wgpk: x25519_dalek::PublicKey = {
        let mut secret = x25519_dalek::StaticSecret::from(wgsk.secret().clone());
        let public = x25519_dalek::PublicKey::from(&secret);
        secret.zeroize();
        public
    };

    let mut wg_public_key = [0u8; 32];
    wg_public_key.copy_from_slice(wgpk.as_bytes());

    let adapter_config = wireguard_nt::SetInterface {
        listen_port: options.listen.map(|s| s.port() + 1),
        public_key: Some(wg_public_key),
        private_key: Some(wg_private_key),
        peers: vec![],
    };

    let adapter_ip = IpNet::from_str("192.168.30.2/24")?;
    if adapter
        .set_default_route(&[adapter_ip.clone()], &adapter_config)
        .is_err()
    {
        bail!("Could not set basic adapter config");
    }

    if adapter.set_config(&adapter_config).is_err() {
        bail!("Could not set basic adapter config");
    }

    if !adapter.up() {
        bail!("Could not bring up adapter");
    }
    let adapter = Rc::new(RefCell::new(adapter));

    let mut srv = Box::new(AppServer::new(
        sk,
        pk,
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

    for peer in options.peers {
        let wgpk = peer.public_keys_dir.join("wgpk");
        let pqpk = peer.public_keys_dir.join("pqpk");
        let psk = peer.public_keys_dir.join("psk");

        let wgpk = Secret::from_slice(
            &base64::engine::general_purpose::STANDARD.decode(std::fs::read_to_string(wgpk)?)?,
        );

        let psk = if psk.exists() {
            Some(SymKey::load_b64(psk))
        } else {
            None
        }
        .transpose()?;

        let pk = SPk::load(&pqpk)?;

        let endpoint = if let Some(mut endpoint) = peer.endpoint {
            endpoint.set_port(endpoint.port() + 1);
            endpoint
        } else {
            bail!("No peer endpoint specified");
        };

        let allowed_ips = peer
            .allowed_ips
            .into_iter()
            .map(|cidr_ip| IpNet::from_str(&cidr_ip).unwrap())
            .collect();

        let mut public_key = [0u8; 32];
        public_key.copy_from_slice(wgpk.secret());

        let wg_peer = wireguard_nt::SetPeer {
            public_key: Some(public_key),
            preshared_key: Some(wgpk.clone().secret().clone()),
            keep_alive: peer.persistent_keepalive.map(|ka| ka as u16),
            endpoint,
            allowed_ips,
        };

        let adapter = WindowsWireguardOut::new(adapter.clone(), adapter_ip.clone(), wg_peer)?;

        srv.add_peer(
            psk.clone(),
            pk,
            None,
            Some(adapter),
            peer.endpoint.map(|x| x.to_string()),
        )?;
    }

    let out = srv.event_loop();

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
