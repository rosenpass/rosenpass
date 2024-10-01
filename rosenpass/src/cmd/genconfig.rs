use super::Command;
use crate::app_server::AppServerTest;
use crate::cli;
use crate::config;
use crate::event_loop::BrokerInterface;
use anyhow::ensure;
use anyhow::Result;

impl Command for cli::GenConfig {
    fn run(self, _: Option<BrokerInterface>, _: Option<AppServerTest>) -> Result<()> {
        println!("GenConfig");
        ensure!(
            self.force || !self.config_file.exists(),
            "config file {0:?} already exists",
            self.config_file
        );

        config::Rosenpass::example_config().store(self.config_file)
    }
}
