use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};

use clap::Parser;
use miette::IntoDiagnostic;

use rosenpass::{
    pqkem::{StaticKEM, KEM},
    protocol::{SPk, SSk},
};

use crate::utils;

/// Genkey command
#[derive(Parser, Debug)]
#[clap(arg_required_else_help = true)]
pub struct Args {
    /// Private key directory
    #[arg(required = true)]
    pub dir: PathBuf,

    /// Force create keys
    #[arg(short, long)]
    pub force: bool,
}

pub fn execute(args: Args) -> miette::Result<()> {
    let dir = args.dir;

    log::debug!("checking if secret keys dir exists");
    if dir.exists() && !args.force {
        miette::bail!("Path already exists!");
    }

    log::debug!("creating secret keys directory");
    fs::create_dir_all(dir.as_path()).into_diagnostic()?;

    log::info!("generating keys");

    log::debug!("generating wireguard secret keys");

    let wgsk = wireguard_keys::Privkey::generate();

    log::debug!("writing wireguard secret keys to file");
    utils::write_to_file(dir.as_path().join("wgsk"), &wgsk.to_string().as_bytes())?;

    log::debug!("generating rosenpass secret key");
    let mut ssk = SSk::random();

    log::debug!("generating rosenpass public key");
    let mut spk = SPk::random();
    StaticKEM::keygen(ssk.secret_mut(), spk.secret_mut()).into_diagnostic()?;

    log::info!("saving keys");

    log::debug!("writing rosenpass keys to file");
    utils::write_to_file(dir.as_path().join("pqsk"), ssk.secret())?;
    utils::write_to_file(dir.as_path().join("pqpk"), spk.secret())?;

    log::debug!("setting perms for secret keys directory");
    fs::set_permissions(dir.as_path(), fs::Permissions::from_mode(0o700)).into_diagnostic()?;

    log::debug!("setting perms for wireguard secret keys file");
    fs::set_permissions(
        dir.as_path().join("wgsk"),
        fs::Permissions::from_mode(0o600),
    )
    .into_diagnostic()?;

    log::debug!("setting perms for rosenpass secret keys file");
    fs::set_permissions(
        dir.as_path().join("pqsk"),
        fs::Permissions::from_mode(0o600),
    )
    .into_diagnostic()?;

    log::debug!("setting perms for rosenpass public keys file");
    fs::set_permissions(
        dir.as_path().join("pqpk"),
        fs::Permissions::from_mode(0o600),
    )
    .into_diagnostic()?;

    Ok(())
}
