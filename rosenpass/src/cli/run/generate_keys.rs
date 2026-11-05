use std::{
    fs::File,
    ops::DerefMut,
    path::Path,
    process::{Command, Stdio},
};

use anyhow::{anyhow, bail};

use crate::internal::{
    cipher_traits::primitives::Kem, ciphers::StaticKem, secret_memory::file::StoreSecret,
    util::file::StoreValue,
};

/// generate secret and public keys, store in files according to the paths passed as arguments
pub fn generate_and_save_keypair(
    generate_directory: Option<&Path>,
    secret_key_file: &Path,
    public_key_file: &Path,
    wg_secret_key: Option<&Path>,
    force: bool,
) -> anyhow::Result<()> {
    // check that we are not overriding something unintentionally
    let mut problems = vec![];
    if !force && public_key_file.exists() {
        problems.push(format!(
            "public-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(public_key_file)?,
        ));
    }
    if !force && secret_key_file.exists() {
        problems.push(format!(
            "secret-key file {:?} exists, refusing to overwrite",
            std::fs::canonicalize(secret_key_file)?,
        ));
    }
    if secret_key_file == public_key_file {
        problems.push("secret key file and public key file have the same path".into());
    }
    if !problems.is_empty() {
        bail!(problems.join("\n"));
    }

    // TODO: maybe set umask?
    // https://github.com/rosenpass/rosenpass/issues/1209
    log::warn!(
        "creating secret/public keys without setting umask, see {}",
        "https://github.com/rosenpass/rosenpass/issues/1209"
    );

    // create directory
    if let Some(generate_directory) = generate_directory {
        log::info!("creating directory \"{}\"", generate_directory.display());
        if generate_directory.exists() {
            bail!(
                "can not create key  directory \"{}\" because it already exists",
                generate_directory.display()
            );
        }
        std::fs::DirBuilder::new()
            .recursive(true) // historically, rp 0.2.3 also creates parent dirs
            .create(generate_directory.clone())
            .map_err(|e| anyhow!(e).context("can not create keys directory"));
    }

    // generate and write secret key and public key
    log::info!("generating static keypair");
    let mut ssk = crate::protocol::basic_types::SSk::random();
    let mut spk = crate::protocol::basic_types::SPk::random();
    StaticKem.keygen(ssk.secret_mut(), spk.deref_mut())?;
    log::info!(
        "storing static secret key to \"{}\"",
        secret_key_file.display()
    );
    ssk.store_secret(secret_key_file)?;
    log::info!(
        "storing static public key to \"{}\"",
        public_key_file.display()
    );
    spk.store(public_key_file)?;

    // generate WireGuard secret key with command line this: `wg genkey > $OUTFILE`
    if let Some(wg_secret_key) = wg_secret_key {
        log::info!(
            "generating WireGuard secret key and writing it to \"{}\"",
            wg_secret_key.display()
        );
        let outfile = File::create(wg_secret_key)
            .map_err(|e| anyhow!(e).context("can not create wg secret key file"))?;
        let exit_code = Command::new("wg")
            .arg("genkey")
            .stdout(Stdio::from(outfile))
            .status()
            .map_err(|e| anyhow!(e).context("can not spawn process \"wg\" to create secret key"))?;
        if !exit_code.success() {
            return Err(anyhow!(
                "\"wg\" returend with {}",
                exit_code
                    .code()
                    .map(|s| format!("exit code {s}"))
                    .unwrap_or_else(|| "unknown exit code".to_string())
            )
            .context("can not create wg secret key"));
        }
    }

    // return
    Ok(())
}
