use std::process::exit;

use cli::{Cli, Command};
use exchange::exchange;
use key::{genkey, pubkey};

mod cli;
mod exchange;
mod key;

#[tokio::main]
async fn main() {
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
    };

    match res {
        Ok(_) => {}
        Err(err) => {
            eprintln!("An error occurred: {}", err);
            exit(1);
        }
    }
}
