use std::{fs, path::PathBuf};

use clap::Parser;
use miette::IntoDiagnostic;
use wireguard_keys::Privkey;

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

    /// Force create keys
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
    let secret_key =
        Privkey::parse(&utils::read_to_string(sk_dir.as_path().join("wgsk"))?).into_diagnostic()?;
    log::debug!("reading rosenpass public keys from file");
    let public_key = utils::read_from_file(sk_dir.as_path().join("pqpk"))?;

    log::info!("generating wireguard public keys");
    let wgpk = if secret_key.valid() {
        secret_key.pubkey()
    } else {
        miette::bail!("wireguard secret key is invalid!");
    };

    log::info!("writing keys to public keys dir");

    log::debug!("writing wireguard public keys");
    utils::write_to_file(pk_dir.as_path().join("wgpk"), &wgpk.to_string().as_bytes())?;

    log::debug!("writing rosenpass public keys");
    utils::write_to_file(pk_dir.as_path().join("pqpk"), &public_key)?;

    Ok(())
}
