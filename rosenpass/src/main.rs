use log::error;
use rosenpass::cli::Cli;
use rosenpass_util::attempt;
use std::process::exit;

/// Catches errors, prints them through the logger, then exits
pub fn main() {
    // default to displaying warning and error log messages only
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("warn")).init();

    let res = attempt!({
        rosenpass_sodium::init()?;
        Cli::run()
    });

    match res {
        Ok(_) => {}
        Err(e) => {
            error!("{e}");
            exit(1);
        }
    }
}
