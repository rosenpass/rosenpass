use super::Command;
use crate::app_server::AppServerTest;
use crate::cli;
use crate::event_loop::BrokerInterface;
use anyhow::bail;
use anyhow::Result;
use std::path::PathBuf;

impl Command for cli::Keygen {
    fn run(
        self,
        broker_interface: Option<BrokerInterface>,
        test_helpers: Option<AppServerTest>,
    ) -> Result<()> {
        log::warn!(
            "The 'keygen' command is deprecated. Please use the 'gen-keys' command instead."
        );

        let mut public_key: Option<PathBuf> = None;
        let mut secret_key: Option<PathBuf> = None;

        // Manual arg parsing, since clap wants to prefix flags with "--"
        let mut args = self.args.iter();
        loop {
            match (args.next().map(|x| x.as_str()), args.next()) {
                (Some("private-key"), Some(opt)) | (Some("secret-key"), Some(opt)) => {
                    secret_key = Some(opt.into());
                }
                (Some("public-key"), Some(opt)) => {
                    public_key = Some(opt.into());
                }
                (Some(flag), _) => {
                    bail!("Unknown option `{}`", flag);
                }
                (_, _) => break,
            };
        }

        Ok(())
    }
}
