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

fn main() {
    let rp = Rp::parse();
    println!("{:?}", rp);
}
