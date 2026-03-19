//! netctl implementation of the WireGuard PSK broker.
//!
//! This module provides an implementation that works on Arch Linux systems by updating
//! netctl profiles to set pre-shared keys.

use std::fmt::Debug;
use std::process::Command;
use std::fs;
use std::path::PathBuf;

use rosenpass_util::b64::b64_encode;
use crate::{SerializedBrokerConfig, WireGuardBroker, WireguardBrokerMio};
use crate::WG_KEY_LEN;

/// A WireGuard broker implementation that uses netctl.
#[derive(Debug, Default)]
pub struct NetctlBroker {
    mio_token: Option<mio::Token>,
}

impl NetctlBroker {
    pub fn new() -> Self {
        Self { mio_token: None }
    }

    fn find_profile(&self, interface: &str) -> anyhow::Result<PathBuf> {
        let profile_dir = PathBuf::from("/etc/netctl");
        for entry in fs::read_dir(profile_dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_file() {
                let content = match fs::read_to_string(&path) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                if content.contains(&format!("Interface={}", interface)) && content.contains("Connection=wireguard") {
                    return Ok(path);
                }
            }
        }
        anyhow::bail!("Could not find netctl profile for interface {}", interface)
    }
}

impl WireGuardBroker for NetctlBroker {
    type Error = anyhow::Error;

    fn set_psk(&mut self, config: SerializedBrokerConfig<'_>) -> Result<(), Self::Error> {
        let interface = std::str::from_utf8(config.interface)?;
        let profile_path = self.find_profile(interface)?;

        // Read the profile
        let mut content = fs::read_to_string(&profile_path)?;

        // Format the PSK as base64
        let mut psk_b64_buf = [0u8; WG_KEY_LEN * 4 / 3 + 4];
        let psk_b64 = b64_encode(config.psk.secret(), &mut psk_b64_buf)?;

        // Update or add PresharedKey
        if content.contains("PresharedKey=") {
            let lines: Vec<String> = content.lines().map(|line| {
                if line.trim().starts_with("PresharedKey=") {
                    format!("PresharedKey={}", psk_b64)
                } else {
                    line.to_string()
                }
            }).collect();
            content = lines.join("\n");
        } else {
            content.push_str(&format!("\nPresharedKey={}\n", psk_b64));
        }

        fs::write(&profile_path, content)?;

        // Restart the profile if it was already active
        let profile_name = profile_path.file_name().unwrap().to_str().unwrap();
        let _ = Command::new("netctl").arg("restart").arg(profile_name).status();

        Ok(())
    }
}

impl WireguardBrokerMio for NetctlBroker {
    type MioError = anyhow::Error;

    fn register(&mut self, _registry: &mio::Registry, token: mio::Token) -> Result<(), Self::MioError> {
        self.mio_token = Some(token);
        Ok(())
    }

    fn process_poll(&mut self) -> Result<(), Self::MioError> {
        Ok(())
    }

    fn unregister(&mut self, _registry: &mio::Registry) -> Result<(), Self::MioError> {
        self.mio_token = None;
        Ok(())
    }

    fn mio_token(&self) -> Option<mio::Token> {
        self.mio_token
    }
}
