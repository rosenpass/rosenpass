use serde::{Deserialize, Serialize};

/// Level of verbosity for [crate::app_server::AppServer]
///
/// The value of the field [crate::app_server::AppServer::verbosity]. See the field documentation
/// for details.
///
/// - TODO: replace this type with [`log::LevelFilter`], also see <https://github.com/rosenpass/rosenpass/pull/246>
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone)]
#[serde(deny_unknown_fields)]
pub enum Verbosity {
    Quiet,
    Verbose,
}

impl Default for Verbosity {
    /// Self::Quiet
    fn default() -> Self {
        Self::Quiet
    }
}
