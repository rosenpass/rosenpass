use std::{fs, process::exit};
use std::iter::Peekable;
use cli::{Cli, Command};
use exchange::exchange;
use key::{genkey, pubkey};
use rosenpass_secret_memory::policy;

mod cli;
mod exchange;
mod key;

#[tokio::main]
async fn main() {
    run(std::env::args().peekable()).await
}

async fn run(args: Peekable<impl Iterator<Item = String>>) {
    #[cfg(feature = "experiment_memfd_secret")]
    policy::secret_policy_try_use_memfd_secrets();
    #[cfg(not(feature = "experiment_memfd_secret"))]
    policy::secret_policy_use_only_malloc_secrets();
    
    let cli = match Cli::parse(args) {
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
        Command::ExchangeConfig { config_file } => {
            let s: String = fs::read_to_string(config_file).expect("cannot read config");
            let mut options: exchange::ExchangeOptions =
                toml::from_str::<exchange::ExchangeOptions>(&s).expect("cannot parse config");
            options.verbose = options.verbose || cli.verbose;
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

#[cfg(test)]
mod tests {
    use rosenpass_secret_memory::policy;
    use crate::{run};

    #[tokio::test]
    async fn smoke_test() {
        let genkey_args: Vec<String> = vec!["rp".to_string(), "genkey".to_string(), "/tmp/keys-dir".to_string()];
        run(genkey_args.into_iter().peekable()).await;
    }
}
