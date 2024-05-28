use std::process::exit;

use cli::{Cli, Command};
use exchange::exchange;
use key::{genkey, pubkey};
use rosenpass_secret_memory::policy;

mod cli;
mod exchange;
mod key;

#[tokio::main]
async fn main() {
    policy::secret_policy_try_use_memfd_secrets();

    let cli = match Cli::parse(std::env::args().peekable()) {
        Ok(cli) => cli,
        Err(err) => {
            eprintln!("{}", err);
            exit(1);
        }
    };

    let command = cli.command.unwrap();

    let res = match command {
        Command::GenKey { private_keys_dir } => genkey(&private_keys_dir),
        Command::PubKey {
            private_keys_dir,
            public_keys_dir,
        } => pubkey(&private_keys_dir, &public_keys_dir),
        Command::Exchange(mut options) => {
            options.verbose = cli.verbose;
            exchange(options).await
        }
        Command::Help => {
            println!("Usage: rp [verbose] genkey|pubkey|exchange [ARGS]...");
            Ok(())
        }
    };

    match res {
        Ok(_) => {}
        Err(err) => {
            eprintln!("An error occurred: {}", err);
            exit(1);
        }
    }
}
