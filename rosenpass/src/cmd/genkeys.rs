use super::Command;
use crate::app_server::AppServerTest;
use crate::cli;
use crate::config;
use crate::event_loop::BrokerInterface;
use crate::protocol::SPk;
use crate::protocol::SSk;
use anyhow::Result;
use anyhow::{bail, ensure};
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_secret_memory::file::StoreSecret;
use rosenpass_util::file::StoreValue;
use std::ops::DerefMut;
use std::path::PathBuf;

impl Command for cli::GenKeys {
    fn run(
        self,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> Result<()> {
        let (pkf, skf) = match (self.config_file, self.public_key, self.secret_key) {
            (Some(config_file), _, _) => {
                ensure!(
                    config_file.exists(),
                    "config file {config_file:?} does not exist"
                );
                let config = config::Rosenpass::load(config_file)?;
                (
                    config.keypair.clone().unwrap().public_key,
                    config.keypair.unwrap().secret_key,
                )
            }
            (_, Some(pkf), Some(skf)) => (pkf, skf),
            _ => {
                bail!("either a config-file or both public-key and secret-key file are required")
            }
        };
        // check that we are not overriding something unintentionally
        let mut problems = vec![];
        if !self.force && pkf.is_file() {
            problems.push(format!(
                "public-key file {pkf:?} exist, refusing to overwrite it"
            ));
        }
        if !self.force && skf.is_file() {
            problems.push(format!(
                "secret-key file {skf:?} exist, refusing to overwrite it"
            ));
        }
        if !problems.is_empty() {
            bail!(problems.join("\n"));
        }

        eprintln!("Generating keypair {pkf:?} and {skf:?}");

        // generate the keys and store them in files
        generate_and_save_keypair(skf, pkf)
    }
}

/// generate secret and public keys, store in files according to the paths passed as arguments
fn generate_and_save_keypair(secret_key: PathBuf, public_key: PathBuf) -> anyhow::Result<()> {
    let mut ssk = SSk::random();
    let mut spk = SPk::random();
    StaticKem::keygen(ssk.secret_mut(), spk.deref_mut())?;
    ssk.store_secret(secret_key)?;
    spk.store(public_key)
}

#[cfg(feature = "internal_testing")]
pub mod testing {
    use super::*;

    pub fn generate_and_save_keypair(
        secret_key: PathBuf,
        public_key: PathBuf,
    ) -> anyhow::Result<()> {
        super::generate_and_save_keypair(secret_key, public_key)
    }
}
