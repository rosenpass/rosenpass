use std::{
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    path::Path,
};

use miette::IntoDiagnostic;
use rosenpass::{
    app_server::{self, AppServer},
    config::{RosenpassPeer, Verbosity},
    protocol::{SPk, SSk, SymKey},
    util::{LoadValue, LoadValueB64},
};

pub fn write_to_file<P>(path: P, content: &[u8]) -> miette::Result<()>
where
    P: AsRef<Path>,
{
    Ok(File::create(path)
        .into_diagnostic()?
        .write_all(&content)
        .into_diagnostic()?)
}

pub fn read_from_file<P>(path: P) -> miette::Result<[u8; 32]>
where
    P: AsRef<Path>,
{
    let mut buf = [0; 32];

    File::open(path)
        .into_diagnostic()?
        .read_exact(&mut buf)
        .into_diagnostic()?;

    Ok(buf)
}

pub fn read_to_string<P>(path: P) -> miette::Result<String>
where
    P: AsRef<Path>,
{
    let mut buf = String::new();

    File::open(path)
        .into_diagnostic()?
        .read_to_string(&mut buf)
        .into_diagnostic()?;

    Ok(buf.trim().to_owned())
}

pub fn start_server(
    sk: SSk,
    pk: SPk,
    listen: Vec<SocketAddr>,
    verbose: bool,
    peers: Vec<RosenpassPeer>,
) -> miette::Result<()> {
    // TODO: find better way to interop between anyhow::Result and miette
    let verbosity = if verbose {
        Verbosity::Verbose
    } else {
        Verbosity::Quiet
    };

    log::info!("verbosity: {verbosity:?}");

    let mut server = Box::new(anyhow_to_miette(AppServer::new(sk, pk, listen, verbosity))?);

    log::info!("server started");

    for peer in peers {
        let psk = anyhow_to_miette(peer.pre_shared_key.map(SymKey::load_b64).transpose())?;

        let pk = anyhow_to_miette(SPk::load(&peer.public_key))?;

        anyhow_to_miette(server.add_peer(
            psk,
            pk,
            peer.key_out,
            peer.wg.map(|cfg| app_server::WireguardOut {
                dev: cfg.device,
                pk: cfg.peer,
                extra_params: cfg.extra_params,
            }),
            peer.endpoint.clone(),
        ))?;
    }

    match server.event_loop() {
        Ok(_) => (),
        Err(e) => log::debug!("EVENT_LOOP: {e}"),
    };

    Ok(())
}

pub fn anyhow_to_miette<T>(result: anyhow::Result<T>) -> miette::Result<T> {
    match result {
        Ok(v) => Ok(v),
        Err(e) => Err(miette::miette!("{e}")),
    }
}
