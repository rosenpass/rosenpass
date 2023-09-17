use log::error;
use rosenpass::{cli::Cli, sodium::sodium_init};
use std::process::exit;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::OpenOptionsExt,
};
use std::{path::PathBuf, process::Command};

use anyhow::bail;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
#[command(propagate_version = true)]
struct Rp {
    // TODO: Use this option to configure the verbosity of the logger
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    Genkey {
        private_keys_dir: PathBuf,
    },
    Pubkey {
        private_keys_dir: PathBuf,
        public_keys_dir: PathBuf,
    },
    // TODO: Add options and arguments for Exchange
    Exchange {},
}

impl Rp {
    fn run(self) -> anyhow::Result<()> {
        use Commands::*;

        match self.command {
            Genkey { private_keys_dir } => {
                match private_keys_dir.try_exists() {
                    Ok(false) => {
                        fs::create_dir_all(&private_keys_dir).or_else(|e| {
                            bail!("Error creating directory {:?}: {}", private_keys_dir, e)
                        })?;

                        let mut options = OpenOptions::new();
                        options.write(true).create(true);

                        if cfg!(unix) {
                            options.mode(0o700);
                        }

                        let wg_key = options.open(private_keys_dir.join("wgsk"))?;
                        let output = Command::new("wg")
                            .args(["genkey"])
                            .stdout(wg_key)
                            .output()?;
                        println!("{:?}", output);
                        match sodium_init().and_then(|()| {
                            let cli = Cli::GenKeys {
                                config_file: None,
                                public_key: Some(private_keys_dir.join("pqsk")),
                                secret_key: Some(private_keys_dir.join("pqpk")),
                                force: false,
                            };
                            cli.run()
                        }) {
                            Ok(_) => {}
                            Err(e) => {
                                error!("{e}");
                                exit(1);
                            }
                        }
                    }
                    Ok(true) => bail!("PRIVATE_KEYS_DIR {:?} already exists", private_keys_dir),
                    Err(e) => bail!("Error checking for directory {:?}: {}", private_keys_dir, e),
                }
                Ok(())
            }
            Pubkey {
                private_keys_dir,
                public_keys_dir,
            } => {
                println!(
                    "Generating public key in {:?} from private key in {:?}",
                    public_keys_dir, private_keys_dir
                );
                Ok(())
            }
            Exchange {} => {
                println!("Exchanging keys");
                Ok(())
            }
        }
    }
}

fn main() {
    env_logger::init();
    let rp = Rp::parse().run();
    println!("{:?}", rp);
}
