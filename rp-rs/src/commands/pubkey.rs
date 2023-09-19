use std::{
    fs,
    io::{Read, Write},
    path::PathBuf,
    process::{Command, Stdio},
};

use clap::Parser;
use miette::IntoDiagnostic;

use crate::utils;

/// Pubkey command
#[derive(Parser, Debug)]
#[clap(arg_required_else_help = true)]
pub struct Args {
    /// Private key directory
    #[arg(required = true)]
    pub dir: PathBuf,

    /// Public key directory
    #[arg(required = true)]
    pub pub_dir: PathBuf,

    #[arg(short, long)]
    pub force: bool,
}

pub fn execute(args: Args) -> miette::Result<()> {
    let sk_dir = args.dir;
    let pk_dir = args.pub_dir;

    log::debug!("checking if public keys dir exists");
    if pk_dir.exists() && !args.force {
        miette::bail!("Public key dir already exists");
    }

    log::debug!("creating public keys directory");
    fs::create_dir_all(pk_dir.as_path()).into_diagnostic()?;

    log::info!("reading keys from secret keys dir");

    log::debug!("reading wireguard secret keys from file");
    let secret_key = utils::read_from_file(sk_dir.as_path().join("wgsk"))?;
    log::debug!("reading rosenpass public keys from file");
    let public_key = utils::read_from_file(sk_dir.as_path().join("pqpk"))?;

    log::info!("generating wireguard public keys");

    log::debug!("spawning wireguard child process to generate public keys");
    let mut wg = Command::new("wg")
        .arg("pubkey")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .into_diagnostic()?;

    log::debug!("passing wireguard secret keys to generate public keys");
    wg.stdin
        .as_mut()
        .ok_or(miette::miette!("Unable to pass secret keys to wg!"))?
        .write_all(&secret_key)
        .into_diagnostic()?;

    log::debug!("waiting for wireguard output");
    wg.wait().into_diagnostic()?;
    let mut output = wg
        .stdout
        .ok_or(miette::miette!("WireGuard didn't output any public key"))?;

    log::debug!("reading wireguard public keys");
    let mut wgpk = Vec::new();
    output.read_to_end(&mut wgpk).into_diagnostic()?;

    log::info!("writing keys to public keys dir");

    log::debug!("writing wireguard public keys");
    utils::write_to_file(pk_dir.as_path().join("wgpk"), &wgpk)?;

    log::debug!("writing rosenpass public keys");
    utils::write_to_file(pk_dir.as_path().join("pqpk"), &public_key)?;

    Ok(())
}
