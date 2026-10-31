use std::{fs, process::exit};

use rosenpass::internal::util::tokio::janitor::ensure_janitor;

use super::cli::{Cli, Command};
use super::exchange::{ExchangeOptions, exchange};
use super::key::{genkey, pubkey};

async fn main_impl() -> anyhow::Result<()> {
    let cli = match Cli::parse(std::env::args().peekable()) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    };

    // init logging
    // TODO: Taken from rosenpass; we should deduplicate the code.
    env_logger::Builder::from_default_env().init(); // sets log level filter from environment (or defaults)

    let command = cli.command.unwrap();

    match command {
        // Command::GenKey { private_keys_dir } => genkey(&private_keys_dir),
        Command::PubKey {
            private_keys_dir,
            public_keys_dir,
        } => pubkey(&private_keys_dir, &public_keys_dir),
        Command::Exchange(mut options) => {
            options.verbose = cli.verbose;
            exchange(options).await
        }
        // done:
        // Command::ExchangeConfig { config_file } => {
        //     let s: String = fs::read_to_string(config_file).expect("cannot read config");
        //     let mut options: ExchangeOptions =
        //         toml::from_str::<ExchangeOptions>(&s).expect("cannot parse config");
        //     options.verbose = options.verbose || cli.verbose;
        //     exchange(options).await
        // }
        Command::Help => {
            println!("Usage: rp [verbose] genkey|pubkey|exchange [ARGS]...");
            Ok(())
        }
    }
}
