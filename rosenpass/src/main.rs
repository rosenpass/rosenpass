use log::error;
use rosenpass::cli::Cli;
use rosenpass_util::attempt;
use std::process::exit;

/// Catches errors, prints them through the logger, then exits
pub fn main() {
    env_logger::init();

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
