use std::{net::SocketAddr, path::PathBuf};

use clap::Parser;
use log::LevelFilter;
use miette::IntoDiagnostic;
use rosenpass::{
    protocol::{SPk, SSk},
    util::LoadValue,
};
use wireguard_rs::{netlink::delete_interface, setup_interface, InterfaceConfiguration};

use crate::utils::{self, anyhow_to_miette};

/// Exchange command
#[derive(Parser, Debug)]
#[clap(arg_required_else_help = true)]
pub struct Args {
    /// Private key directory
    #[arg(required = true)]
    pub dir: PathBuf,

    // Device name
    #[arg(short, long, required = true)]
    pub dev: String,

    // Listening address
    #[arg(short, long)]
    pub listen: SocketAddr,
}

pub fn execute(args: Args, level: LevelFilter) -> miette::Result<()> {
    let device = format!("{}0", args.dev);
    let sk_dir = args.dir;

    let pqsk_path = sk_dir.as_path().join("pqsk");
    let pqpk_path = sk_dir.as_path().join("pqpk");

    let listen = args.listen;
    let listen_addr = listen.ip();
    let listen_port = listen.port();

    let wgsk_path = sk_dir.as_path().join("wgsk");
    let wgsk = utils::read_to_string(&wgsk_path)?;

    log::info!("setting up wireguard interface");
    setup_interface(
        &device,
        false,
        &InterfaceConfiguration {
            name: device.clone(),
            prvkey: wgsk,
            address: listen_addr.to_string(),
            port: listen_port as u32,
            peers: vec![],
        },
    )
    .into_diagnostic()?;

    log::debug!("setting up ctrlc handler!");
    ctrlc::set_handler(move || {
        log::info!("^C recieved, exiting...");
        if let Err(e) = delete_interface(&device.clone()).into_diagnostic() {
            log::error!("{e}");
        }
    })
    .into_diagnostic()?;

    log::info!("loading rosenpass keys");
    let sk = anyhow_to_miette(SSk::load(pqsk_path))?;
    let pk = anyhow_to_miette(SPk::load(pqpk_path))?;

    log::info!("staring rosenpass server");
    utils::start_server(
        sk,
        pk,
        vec![SocketAddr::new(listen_addr, listen_port + 1)],
        level > LevelFilter::Warn,
        vec![],
    )?;

    Ok(())
}
