use std::{path::PathBuf, process::Command, fs::{self, File}};

use anyhow::bail;
use clap::{Parser, Subcommand};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about)]
#[command(propagate_version = true)]
struct Rp {
    #[arg(short, long)]
    explain: bool,

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
                        println!("Generating key pair in {:?}", private_keys_dir);
                        let _ = fs::create_dir_all(&private_keys_dir).or_else(|e| {
                            bail!("Error creating directory {:?}: {}", private_keys_dir, e)
                        });
                        let wg_key = File::create(private_keys_dir.join("wgsk"))?;
                        let wireguard_keygen = Command::new("wg").args(["genkey"]).stdout(wg_key).output()?;
                        println!("{wireguard_keygen:?}");
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
    let rp = Rp::parse().run();
    println!("{:?}", rp);
}
