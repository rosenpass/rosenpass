use clap::Parser;
use rosenpass::broker;
use rosenpass::cli::{Cli, Commands};
use rosenpass::cmd::Command;

pub fn main() -> anyhow::Result<()> {
    {
        use rosenpass_secret_memory as SM;
        #[cfg(feature = "experiment_memfd_secret")]
        SM::secret_policy_try_use_memfd_secrets();
        #[cfg(not(feature = "experiment_memfd_secret"))]
        SM::secret_policy_use_only_malloc_secrets();
    }

    let cli = Cli::parse();

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let broker_interface = broker::get_broker_interface(&cli);

    match cli.command {
        Commands::ExchangeConfig(exchangeconfig) => exchangeconfig.run(broker_interface, None),
        Commands::Exchange(exchange) => exchange.run(broker_interface, None),
        Commands::GenConfig(genconfig) => genconfig.run(broker_interface, None),
        Commands::GenKeys(genkeys) => genkeys.run(broker_interface, None),
        Commands::Keygen(keygen) => keygen.run(broker_interface, None),
        Commands::Validate(validate) => validate.run(broker_interface, None),
        Commands::Man(man) => man.run(broker_interface, None),
    }
}
