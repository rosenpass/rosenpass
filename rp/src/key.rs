use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use wireguard_keys::Privkey;

use rosenpass::protocol::{SSk, SPk};
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_secret_memory::file::StoreSecret as _;

pub fn genkey(private_keys_dir: &Path) -> Result<()> {
    if private_keys_dir.exists() {
        return Err(anyhow!("Directory {:?} already exists", private_keys_dir));
    }

    fs::create_dir_all(private_keys_dir)?;

    let wgsk_path = private_keys_dir.join("wgsk");
    let pqsk_path = private_keys_dir.join("pqsk");
    let pqpk_path = private_keys_dir.join("pqpk");

    let wgsk = Privkey::generate();
    fs::write(wgsk_path, wgsk.to_base64())?;

    let mut pqsk = SSk::random();
    let mut pqpk = SPk::random();
    StaticKem::keygen(pqsk.secret_mut(), pqpk.secret_mut())?;
    pqsk.store_secret(pqsk_path)?;
    pqpk.store_secret(pqpk_path)?;

    Ok(())
}

pub fn pubkey(private_keys_dir: &Path, public_keys_dir: &Path) -> Result<()> {
    if public_keys_dir.exists() {
        return Err(anyhow!("Directory {:?} already exists", public_keys_dir));
    }

    fs::create_dir_all(public_keys_dir)?;

    let private_wgsk = private_keys_dir.join("wgsk");
    let public_wgpk = public_keys_dir.join("wgpk");
    let private_pqpk = private_keys_dir.join("pqpk");
    let public_pqpk = public_keys_dir.join("pqpk");

    let wgsk = Privkey::from_base64(&fs::read_to_string(private_wgsk)?)?;
    let wgpk = wgsk.pubkey();
    fs::write(public_wgpk, wgpk.to_base64())?;

    fs::copy(private_pqpk, public_pqpk)?;

    Ok(())
}
