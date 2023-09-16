use std::path::PathBuf;

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
    fn run(self) {
        use Commands::*;

        match self.command {
            Genkey { private_keys_dir } => {
                println!("Generating key pair in {:?}", private_keys_dir);
            }
            Pubkey {
                private_keys_dir,
                public_keys_dir,
            } => {
                println!(
                    "Generating public key in {:?} from private key in {:?}",
                    public_keys_dir, private_keys_dir
                );
            }
            Exchange {} => {
                println!("Exchanging keys");
            }
        }
    }
}



fn main() {
    let rp = Rp::parse().run();
    println!("{:?}", rp);
}
