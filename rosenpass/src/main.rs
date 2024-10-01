use clap::CommandFactory;
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

    if let Some(shell) = cli.print_completions {
        let mut cli = Cli::command();
        clap_complete::generate(shell, &mut cli, "rosenpass", &mut std::io::stdout());
        return Ok(());
    }

    if cli.print_manpage {
        let cli = Cli::command();
        let man = clap_mangen::Man::new(cli);
        man.render(&mut std::io::stdout())?;
        return Ok(());
    }

    env_logger::Builder::new()
        .filter_level(cli.verbose.log_level_filter())
        .init();

    let mut broker_interface = None;
    match cli.command {
        Some(Commands::ExchangeConfig(_)) | Some(Commands::Exchange(_)) => {
            broker_interface = broker::get_broker_interface(&cli);
        }
        _ => {}
    }

    match cli.command {
        Some(Commands::ExchangeConfig(exchangeconfig)) => {
            exchangeconfig.run(broker_interface, None)
        }
        Some(Commands::Exchange(exchange)) => exchange.run(broker_interface, None),
        Some(Commands::GenConfig(genconfig)) => genconfig.run(None, None),
        Some(Commands::GenKeys(genkeys)) => genkeys.run(None, None),
        Some(Commands::Keygen(keygen)) => keygen.run(None, None),
        Some(Commands::Validate(validate)) => validate.run(None, None),
        None => Ok(()), // calp print help if no command is given
    }
}
