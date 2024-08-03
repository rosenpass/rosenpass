use clap::Parser;
use log::error;
use rosenpass::cli::CliArgs;
use std::process::exit;

/// Catches errors, prints them through the logger, then exits
pub fn main() {
    // parse CLI arguments
    let args = CliArgs::parse();

    {
        use rosenpass_secret_memory as SM;
        #[cfg(feature = "experiment_memfd_secret")]
        SM::secret_policy_try_use_memfd_secrets();
        #[cfg(not(feature = "experiment_memfd_secret"))]
        SM::secret_policy_use_only_malloc_secrets();
    }

    // init logging
    {
        let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)
        if let Some(level) = args.get_log_level() {
            log::debug!("setting log level to {:?} (set via CLI parameter)", level);
            log_builder.filter_level(level); // set log level filter from CLI args if available
        }
        log_builder.init();

        // // check the effectiveness of the log level filter with the following lines:
        // use log::{debug, error, info, trace, warn};
        // trace!("trace dummy");
        // debug!("debug dummy");
        // info!("info dummy");
        // warn!("warn dummy");
        // error!("error dummy");
    }

    match args.command.run(None) {
        Ok(_) => {}
        Err(e) => {
            error!("{e}");
            exit(1);
        }
    }
}
