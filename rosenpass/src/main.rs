use log::error;
use rosenpass::cli::Cli;
use std::process::exit;

/// Catches errors, prints them through the logger, then exits
pub fn main() {
    // default to displaying warning and error log messages only
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    match Cli::run() {
        Ok(_) => {}
        Err(e) => {
            error!("{e}");
            exit(1);
        }
    }
}
