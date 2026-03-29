use std::{fs, path::PathBuf, process::exit};

use clap::{Parser, Subcommand};
use rosenpass_util::tokio::janitor::ensure_janitor;

use rosenpass_secret_memory::policy;

use crate::{
    cli::{Cli, Command},
    exchange::{exchange, ExchangeOptions},
    key::{genkey, pubkey},
    net::manager::{create_network_manager, NetworkManagerType},
};

mod api;
mod app_server;
mod cli;
mod config;
mod crypto;
mod exchange;
mod key;
mod msg;
mod net;
mod peer;
mod protocol;
mod util;

#[tokio::main]
pub async fn main() -> anyhow::Result<()> {
    #[cfg(feature = "experiment_memfd_secret")]
    policy::secret_policy_try_use_memfd_secrets();
    #[cfg(not(feature = "experiment_memfd_secret"))]
    policy::secret_policy_use_only_malloc_secrets();

    ensure_janitor(async move { main_impl().await }).await
}

async fn main_impl() -> anyhow::Result<()> {
    let cli = match Cli::parse(std::env::args().peekable()) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    };

    // Detect and initialize network manager
    let network_manager = create_network_manager();
    let nm_type = match detect_network_manager() {
        NetworkManagerType::Systemd => "systemd-networkd",
        NetworkManagerType::Netctl => "netctl",
        NetworkManagerType::None => "none",
    };
    log::info!("Using network manager: {}", nm_type);

    // init logging
    env_logger::Builder::from_default_env().init();

    let command = cli.command.unwrap();

    match command {
        Command::GenKey { private_keys_dir } => genkey(&private_keys_dir),
        Command::PubKey {
            private_keys_dir,
            public_keys_dir,
        } => pubkey(&private_keys_dir, &public_keys_dir),
        Command::Exchange(mut options) => {
            options.verbose = cli.verbose;
            exchange(options).await
        }
        Command::ExchangeConfig { config_file } => {
            let s: String = fs::read_to_string(config_file).expect("cannot read config");
            let mut options: ExchangeOptions =
                toml::from_str::<ExchangeOptions>(&s).expect("cannot parse config");
            options.verbose = options.verbose || cli.verbose;
            exchange(options).await
        }
        Command::Help => {
            println!("Usage: rosenpass [verbose] genkey|pubkey|exchange [ARGS]...");
            Ok(())
        }
    }
}