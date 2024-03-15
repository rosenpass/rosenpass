use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;

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

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub fn exchange(_: ExchangeOptions) -> Result<()> {
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

    pub async fn wg_set(
        genetlink: &mut GenetlinkHandle,
        index: u32,
        mut attr: Vec<WgDeviceAttrs>,
    ) -> Result<()> {
        use futures_util::StreamExt as _;
        use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
        use netlink_packet_generic::GenlMessage;
        use netlink_packet_wireguard::{Wireguard, WireguardCmd};

        attr.insert(0, WgDeviceAttrs::IfIndex(index));

        let wgc = Wireguard {
            cmd: WireguardCmd::SetDevice,
            nlas: attr,
        };

        let genl = GenlMessage::from_payload(wgc);
        let mut nlmsg = NetlinkMessage::from(genl);
        nlmsg.header.flags = NLM_F_REQUEST | NLM_F_ACK;

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
    use std::fs::{self, read_to_string};

    use anyhow::anyhow;
    use base64::Engine;
    use netlink_packet_wireguard::{constants::WG_KEY_LEN, nlas::WgDeviceAttrs};
    use rosenpass::{
        app_server::{AppServer, WireguardOut},
        config::Verbosity,
        protocol::{SPk, SSk, SymKey},
    };
    use rosenpass_util::file::{LoadValue as _, LoadValueB64};
    use zeroize::Zeroize;

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

    let mut wgsk_b64 = read_to_string(wgsk_path)?;

    let wgsk_maybe = base64::engine::general_purpose::STANDARD.decode(&wgsk_b64);

    wgsk_b64.zeroize();

    let mut wgsk: [u8; WG_KEY_LEN] = wgsk_maybe?.try_into().map_err(|_| anyhow!("WireGuard secret key is not {} bytes long.", WG_KEY_LEN))?;

    let mut attr: Vec<WgDeviceAttrs> = Vec::with_capacity(2);
    attr.push(WgDeviceAttrs::PrivateKey(wgsk));

    if let Some(listen) = options.listen {
        if listen.port() == u16::MAX {
            return Err(anyhow!("You may not use {} as the listen port.", u16::MAX));
        }

        attr.push(WgDeviceAttrs::ListenPort(listen.port() + 1));
    }

    netlink::wg_set(&mut genetlink, link_index, attr).await?;

    wgsk.zeroize();

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
            Some(WireguardOut {
                dev: link_name.clone(),
                pk: fs::read_to_string(wgpk)?,
                extra_params,
            }),
            peer.endpoint.map(|x| x.to_string()),
        )?;
    }

    let out = srv.event_loop();

    netlink::link_cleanup(&rtnetlink, link_index).await?;

    out
}
