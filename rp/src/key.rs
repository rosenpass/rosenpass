use std::{fs, path::Path};

use anyhow::{anyhow, Result};
use wireguard_keys::Privkey;

use rosenpass::protocol::{SPk, SSk};
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

#[cfg(test)]
mod tests {
    use std::fs;

    use rosenpass::protocol::{SPk, SSk};
    use rosenpass_util::file::LoadValue;
    use tempfile::tempdir;
    use wireguard_keys::{Privkey, Pubkey};

    use crate::key::{genkey, pubkey};

    #[test]
    fn it_works() {
        let private_keys_dir = tempdir().unwrap();
        fs::remove_dir(private_keys_dir.path()).unwrap();

        // Guranteed to have 16MB of stack size
        stacker::grow(8 * 1024 * 1024, || {
            assert!(genkey(private_keys_dir.path()).is_ok());
        });

        assert!(private_keys_dir.path().exists());
        assert!(private_keys_dir.path().is_dir());
        assert!(SPk::load(private_keys_dir.path().join("pqpk")).is_ok());
        assert!(SSk::load(private_keys_dir.path().join("pqsk")).is_ok());
        assert!(Privkey::from_base64(
            &fs::read_to_string(private_keys_dir.path().join("wgsk")).unwrap()
        )
        .is_ok());

        let public_keys_dir = tempdir().unwrap();
        fs::remove_dir(public_keys_dir.path()).unwrap();

        // Guranteed to have 16MB of stack size
        stacker::grow(8 * 1024 * 1024, || {
            assert!(pubkey(private_keys_dir.path(), public_keys_dir.path()).is_ok());
        });

        assert!(public_keys_dir.path().exists());
        assert!(public_keys_dir.path().is_dir());
        assert!(SPk::load(public_keys_dir.path().join("pqpk")).is_ok());
        assert!(Pubkey::from_base64(
            &fs::read_to_string(public_keys_dir.path().join("wgpk")).unwrap()
        )
        .is_ok());

        let pk_1 = fs::read(private_keys_dir.path().join("pqpk")).unwrap();
        let pk_2 = fs::read(public_keys_dir.path().join("pqpk")).unwrap();
        assert_eq!(pk_1, pk_2);
    }
}
