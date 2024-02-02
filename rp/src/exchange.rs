use std::{net::SocketAddr, path::PathBuf};

use anyhow::Result;

pub struct ExchangePeer {
    public_keys_dir: PathBuf,
    endpoint: Option<SocketAddr>,
    persistent_keepalive: Option<u32>,
    allowed_ips: Option<String>,
}

pub struct ExchangeOptions {
    private_keys_dir: PathBuf,
    dev: Option<String>,
    listen: Option<SocketAddr>,
    peers: Vec<ExchangePeer>,
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
pub fn exchange(_: ExchangeOptions) -> Result<()> {
    Err(anyhow!("Your system {} is not yet supported. We are happy to receive patches to address this :)", std::env::consts::OS))
}

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
pub async fn exchange(options: ExchangeOptions) -> Result<()> {
    use std::fs::read_to_string;

    use futures_util::{StreamExt, TryStreamExt};
    use netlink_packet_route::link::LinkAttribute;
    use netlink_packet_utils::nla::DefaultNla;
    use rosenpass::{app_server::{AppServer, WireguardOut}, config::Verbosity, protocol::{SPk, SSk, SymKey}};
    use rosenpass_util::file::{LoadValue as _, LoadValueB64};
    use rtnetlink::new_connection;
    use wireguard_keys::Privkey;

    let (_, netlink, _) = new_connection()?;

    let link_name = options.dev.unwrap_or("rosenpass0".to_string());

    // add the link
    netlink.link().add()
        .wireguard(link_name.clone())
        .execute()
        .await?;

    // retrieve the link to be able to up it
    let link = netlink.link().get()
        .match_name(link_name.clone())
        .execute()
        .into_stream()
        .into_future()
        .await
        .0.unwrap().unwrap();

    // up the link
    netlink.link().set(link.header.index)
        .up()
        .execute()
        .await?;

    // Deploy the classic wireguard private key
    let mut lsr = netlink.link().set(link.header.index);
    let msg = lsr.message_mut();

    let wgsk_path = options.private_keys_dir.join("wgsk");
    
    let wgsk = Privkey::from_base64(&read_to_string(wgsk_path)?)?;

    msg.attributes.push(LinkAttribute::Other(DefaultNla::new(
        3, // PrivateKey
        wgsk.to_vec(),
    )));


    if let Some(listen) = options.listen {
        msg.attributes.push(LinkAttribute::Other(DefaultNla::new(
            6, // ListenPort
            (listen.port() + 1).to_ne_bytes().to_vec(),
        )));
    }

    lsr.execute().await?;

    ctrlc_async::set_async_handler(async move {
        netlink.link().del(link.header.index).execute().await.expect("Failed to bring down WireGuard network interface");
    })?;

    let pgsk = options.private_keys_dir.join("pgsk");
    let pgpk = options.private_keys_dir.join("pgpk");

    let sk = SSk::load(&pgpk)?;
    let pk = SPk::load(&pgsk)?;

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
        Verbosity::Quiet,
    )?);

    for peer in options.peers {
        let wgpk = peer.public_keys_dir.join("wgpk");
        let pqpk = peer.public_keys_dir.join("pqpk");
        let psk = peer.public_keys_dir.join("psk");

        let mut extra_params: Vec<String> = Vec::with_capacity(6);
        if let Some(endpoint) = peer.endpoint {
            extra_params.push("endpoint".to_string());
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
            }.transpose()?,
            SPk::load(&pqpk)?,
            None,
            Some(WireguardOut {
                dev: link_name.clone(),
                pk: wgpk.to_string_lossy().to_string(),
                extra_params,
            }),
            if let Some(endpoint) = peer.endpoint {
                Some(endpoint.to_string())
            } else {
                None
            },
        )?;
    }

    srv.event_loop()
}
