use clap::Parser;
use clap_verbosity_flag::Verbosity;
use env_logger::{Builder, WriteStyle};
use log::LevelFilter;
use rosenpass::sodium::sodium_init;

use commands::{exchange, genkey, pubkey};

mod commands;
mod utils;

/// RP implemented in rust
#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
#[clap(arg_required_else_help = true)]
struct Args {
    #[command(subcommand)]
    command: Command,

    /// Verbosity level
    #[command(flatten)]
    verbose: Verbosity,
}

#[derive(Parser, Debug)]
enum Command {
    #[clap(alias = "gk")]
    Genkey(genkey::Args),
    #[clap(alias = "pk")]
    Pubkey(pubkey::Args),
    #[clap(alias = "ex")]
    Exchange(exchange::Args),
}

fn main() {
    if let Err(err) = execute(Args::parse()) {
        eprintln!("{err:?}");
        std::process::exit(1);
    }
}

fn execute(args: Args) -> miette::Result<()> {
    if let Err(e) = sodium_init() {
        miette::bail!("{e}");
    }

    let level = match args.verbose.log_level_filter() {
        clap_verbosity_flag::LevelFilter::Off => LevelFilter::Off,
        clap_verbosity_flag::LevelFilter::Error => LevelFilter::Error,
        clap_verbosity_flag::LevelFilter::Warn => LevelFilter::Warn,
        clap_verbosity_flag::LevelFilter::Info => LevelFilter::Info,
        clap_verbosity_flag::LevelFilter::Debug => LevelFilter::Debug,
        clap_verbosity_flag::LevelFilter::Trace => LevelFilter::Trace,
    };

    Builder::new()
        .filter(None, level)
        .write_style(WriteStyle::Always)
        .init();

    match args.command {
        Command::Genkey(args) => genkey::execute(args),
        Command::Pubkey(args) => pubkey::execute(args),
        Command::Exchange(args) => exchange::execute(args, level),
    }
}
