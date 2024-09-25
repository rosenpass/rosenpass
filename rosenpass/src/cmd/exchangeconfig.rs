use super::Command;
use crate::app_server::AppServerTest;
use crate::cli;
use crate::config::Rosenpass;
use crate::event_loop;
use crate::event_loop::BrokerInterface;
use anyhow::ensure;
use anyhow::Result;

impl Command for cli::ExchangeConfig {
    fn run(
        self,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> Result<()> {
        eprintln!("ExchangeConfig");
        ensure!(
            self.config_file.exists(),
            "config file '{0:?}' does not exist",
            self.config_file
        );

        let config = Rosenpass::load(self.config_file)?;
        config.validate()?;
        config.check_usefullness()?;

        event_loop::event_loop(config, None, None)?;
        Ok(())
    }
}
