use super::Command;
use crate::app_server::AppServerTest;
use crate::cli;
use crate::event_loop::BrokerInterface;
use anyhow::Result;

impl Command for cli::Man {
    fn run(self, _: Option<BrokerInterface>, _: Option<AppServerTest>) -> Result<()> {
        let man_cmd = std::process::Command::new("man")
            .args(["1", "rosenpass"])
            .status();

        if !(man_cmd.is_ok() && man_cmd.unwrap().success()) {
            println!(include_str!(env!("ROSENPASS_MAN")));
        }

        Ok(())
    }
}
