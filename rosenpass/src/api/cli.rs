use std::path::PathBuf;

use clap::Args;

use crate::config::Rosenpass as RosenpassConfig;

use super::config::ApiConfig;

/// Additional command line arguments for the API
#[cfg(feature = "experiment_api")]
#[derive(Args, Debug)]
pub struct ApiCli {
    /// Where in the file-system to create the unix socket the rosenpass API will be listening for
    /// connections on.
    #[arg(long)]
    api_listen_path: Vec<PathBuf>,

    /// When rosenpass is called from another process, the other process can open and bind the
    /// unix socket for the Rosenpass API to use themselves, passing it to this process. In Rust this can be achieved
    /// using the [command-fds](https://docs.rs/command-fds/latest/command_fds/) crate.
    #[arg(long)]
    api_listen_fd: Vec<i32>,

    /// When rosenpass is called from another process, the other process can connect the unix socket for the API
    /// themselves, for instance using the `socketpair(2)` system call.
    #[arg(long)]
    api_stream_fd: Vec<i32>,
}

impl ApiCli {
    /// Copy the parameters set here into the [RosenpassConfig].
    /// Forwards to [Self::apply_to_api_config]:
    pub fn apply_to_config(&self, cfg: &mut RosenpassConfig) -> anyhow::Result<()> {
        self.apply_to_api_config(&mut cfg.api)
    }

    /// Fills the values from [ApiConfig::listen_path], [ApiConfig::listen_fd], and
    /// [ApiConfig::stream_fd] with the values from [Self]
    pub fn apply_to_api_config(&self, cfg: &mut ApiConfig) -> anyhow::Result<()> {
        cfg.listen_path.extend_from_slice(&self.api_listen_path);
        cfg.listen_fd.extend_from_slice(&self.api_listen_fd);
        cfg.stream_fd.extend_from_slice(&self.api_stream_fd);
        Ok(())
    }
}
