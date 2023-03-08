use std::path::PathBuf;

use clap::{Parser, Subcommand};

// Usage: ../rp-old [explain] [verbose] genkey|pubkey|exchange [ARGS]...

/// Simple program to greet a person
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Explain what is done
    #[arg(short, long)]
    explain: bool,

    /// Be verbose about what's going on
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

/// Doc comment
#[derive(Subcommand, Debug)]
// #[command(PARENT CMD ATTRIBUTE)]
enum Command {
    /// Generate a keypair
    // --- Requirements ---
    // requires wireguard
    // should not exist before
    // should be dir after
    // should contain three files after pqpk, pqsk, wgsk
    Genkey {
        private_keys_dir: PathBuf,
    },

    /// Generate public keys
    // --- Requirements ---
    // requires wireguard
    // requires private_keys_dir to exist
    // should create public_keys_dir
    // should copy pqpk from private_ to public_keys_dir
    // should generate wgpk to public_keys_dir
    Pubkey {
        private_keys_dir: PathBuf,
        public_keys_dir: PathBuf,
    },

    Exchange {},
}
fn main() {
    let args = Cli::parse();

    println!("{args:#?}");
}
