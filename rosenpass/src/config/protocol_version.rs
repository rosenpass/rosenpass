use serde::{Deserialize, Serialize};

/// The protocol version to be used by a peer.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Copy, Clone, Default)]
#[serde(deny_unknown_fields)]
pub enum ProtocolVersion {
    #[default]
    V02,
    V03,
}
