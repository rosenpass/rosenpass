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
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    use std::fs::{self, read_to_string};

    use futures_util::{StreamExt, TryStreamExt};
    use netlink_packet_core::{NetlinkMessage, NetlinkPayload};
    use netlink_packet_generic::GenlMessage;
    use netlink_packet_wireguard::{nlas::WgDeviceAttrs, Wireguard, WireguardCmd};
    use rosenpass::{
        app_server::{AppServer, WireguardOut},
        config::Verbosity,
        protocol::{SPk, SSk, SymKey},
    };
    use rosenpass_util::file::{LoadValue as _, LoadValueB64};
    use wireguard_keys::Privkey;

    let (connection, rtnetlink, _) = rtnetlink::new_connection()?;
    tokio::spawn(connection);

    let link_name = options.dev.unwrap_or("rosenpass0".to_string());

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

    // Deploy the classic wireguard private key
    let (connection, mut genetlink, _) = genetlink::new_connection()?;
    tokio::spawn(connection);

    let mut nlas: Vec<WgDeviceAttrs> =
        Vec::with_capacity(if options.listen.is_some() { 3 } else { 2 });

    nlas.push(WgDeviceAttrs::IfIndex(link.header.index));

    let wgsk_path = options.private_keys_dir.join("wgsk");
    let wgsk = Privkey::from_base64(&read_to_string(wgsk_path)?)?;

    nlas.push(WgDeviceAttrs::PrivateKey(*wgsk));

    if let Some(listen) = options.listen {
        nlas.push(WgDeviceAttrs::ListenPort(listen.port() + 1));
    }

    let wgc = Wireguard {
        cmd: WireguardCmd::SetDevice,
        nlas,
    };

    let genl = GenlMessage::from_payload(wgc);
    let nlmsg = NetlinkMessage::from(genl);

    let (res, _) = genetlink.request(nlmsg).await?.into_future().await;
    if let Some(res) = res {
        let res = res?;
        match res.payload {
            NetlinkPayload::Error(err) => return Err(err.to_io().into()),
            _ => {}
        };
    }

    ctrlc_async::set_async_handler(async move {
        rtnetlink
            .link()
            .del(link.header.index)
            .execute()
            .await
            .expect("Failed to bring down WireGuard network interface");
    })?;

    let pqsk = options.private_keys_dir.join("pqsk");
    let pqpk = options.private_keys_dir.join("pqpk");

    let sk = SSk::load(&pqsk)?;
    let pk = SPk::load(&pqpk)?;

    let mut srv = Box::new(AppServer::new(
        sk,
        pk,
        if let Some(listen) = options.listen {
            let mut v: Vec<SocketAddr> = Vec::with_capacity(1);
            v.push(listen);
            v
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

    srv.event_loop()
}
