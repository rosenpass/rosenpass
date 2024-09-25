use super::Command;
use crate::app_server::AppServerTest;
use crate::cli;
use crate::config::Rosenpass;
use crate::event_loop::BrokerInterface;
use crate::event_loop::{self};
use anyhow::Result;

impl Command for cli::Exchange {
    fn run(
        self,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> Result<()> {
        eprintln!("Exchange");
        let mut rest_of_args = self.rest_of_args.clone();
        rest_of_args.insert(0, self.first_arg.clone());
        let args = rest_of_args;
        let mut config = Rosenpass::parse_args(args)?;

        if let Some(p) = self.config_file {
            config.store(p.clone())?;
            config.config_file_path.clone_from(&p);
        }
        config.validate()?;
        config.check_usefullness()?;

        event_loop::event_loop(config, None, None)?;
        Ok(())
    }
}
