use std::path::PathBuf;

use mio::net::UnixListener;
use rosenpass_util::mio::{UnixListenerExt, UnixStreamExt};
use serde::{Deserialize, Serialize};

use crate::app_server::AppServer;

/// Configuration options for the Rosenpass API
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq)]
pub struct ApiConfig {
    /// Where in the file-system to create the unix socket the rosenpass API will be listening for
    /// connections on
    pub listen_path: Vec<PathBuf>,

    /// When rosenpass is called from another process, the other process can open and bind the
    /// unix socket for the Rosenpass API to use themselves, passing it to this process. In Rust this can be achieved
    /// using the [command-fds](https://docs.rs/command-fds/latest/command_fds/) crate.
    pub listen_fd: Vec<i32>,

    /// When rosenpass is called from another process, the other process can connect the unix socket for the API
    /// themselves, for instance using the `socketpair(2)` system call.
    pub stream_fd: Vec<i32>,
}

impl ApiConfig {
    /// Construct appropriate [UnixListener]s for each of the API
    /// listeners and connections configured in [Self] and invoke
    /// [AppServer::add_api_listener] for each to add them to the
    /// [AppServer].
    pub fn apply_to_app_server(&self, srv: &mut AppServer) -> anyhow::Result<()> {
        for path in self.listen_path.iter() {
            srv.add_api_listener(UnixListener::bind(path)?)?;
        }

        for fd in self.listen_fd.iter() {
            srv.add_api_listener(UnixListenerExt::claim_fd(*fd)?)?;
        }

        for fd in self.stream_fd.iter() {
            srv.add_api_connection(UnixStreamExt::claim_fd(*fd)?)?;
        }

        Ok(())
    }

    /// Sum of all the API sources configured in here
    pub fn count_api_sources(&self) -> usize {
        self.listen_path.len() + self.listen_fd.len() + self.stream_fd.len()
    }

    /// Checks if [Self::count_api_sources] is greater than zero
    pub fn has_api_sources(&self) -> bool {
        self.count_api_sources() > 0
    }
}
