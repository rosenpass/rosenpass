use protocol::{HandshakeStateMachine, PeerId, PeerPtr, SessionId};

#[macro_use]
pub mod util;
#[macro_use]
pub mod sodium;
pub mod coloring;
#[rustfmt::skip]
pub mod labeled_prf;
pub mod app_server;
pub mod cli;
pub mod config;
pub mod msgs;
pub mod pqkem;
pub mod prftree;
pub mod protocol;

#[derive(thiserror::Error, Debug)]
pub enum RosenpassError {
    #[error("error in OQS")]
    Oqs,

    #[error("error from external library while calling OQS")]
    OqsExternalLib,

    #[error("error while calling into libsodium")]
    LibsodiumError(&'static str),

    #[error("buffer size mismatch, required {required_size} but only found {actual_size}")]
    BufferSizeMismatch {
        required_size: usize,
        actual_size: usize,
    },

    #[error("invalid message type")]
    InvalidMessageType(u8),

    #[error("peer id {0:?} already taken")]
    PeerIdAlreadyTaken(PeerId),

    #[error("session id {0:?} already taken")]
    SessionIdAlreadyTaken(SessionId),

    #[error("{0}")]
    NotImplemented(&'static str),

    #[error("{0}")]
    ConfigError(String),

    #[error("see last log messages")]
    RuntimeError,

    #[error("{0}")]
    IoError(#[from] std::io::Error),

    #[error("{0}")]
    TomlDeserError(#[from] toml::de::Error),

    #[error("{0}")]
    TomlSerError(#[from] toml::ser::Error),

    #[error("invalid session id {0:?} was used")]
    InvalidSessionId(SessionId),

    #[error("no session available")]
    NoSession,
    #[error("the peer {0:?} does not exist")]
    NoSuchPeer(PeerPtr),

    #[error("the peer id {0:?} does not exist")]
    NoSuchPeerId(PeerId),

    #[error("the session {0:?} does not exist")]
    NoSuchSessionId(SessionId),

    #[error("no current handshake with peer {0:?}")]
    NoCurrentHs(PeerPtr),
    // TODO implement Display for Peer/Session ptr?
    #[error("message seal broken")]
    SealBroken,

    #[error("received empty message")]
    EmptyMessage,

    #[error("biscuit with invalid number")]
    InvalidBiscuitNo,

    #[error("got unexpected message")]
    UnexpectedMessage {
        session: SessionId,
        expected: Option<HandshakeStateMachine>,
        got: Option<HandshakeStateMachine>,
    },

    #[error("???")]
    StaleNonce,
}

/// Rosenpass Result type
pub type Result<T> = core::result::Result<T, RosenpassError>;

impl RosenpassError {
    /// Helper function to check a buffer size
    fn check_buffer_size(required_size: usize, actual_size: usize) -> Result<()> {
        if required_size != actual_size {
            Err(Self::BufferSizeMismatch {
                required_size,
                actual_size,
            })
        } else {
            Ok(())
        }
    }
}

/// Extension trait to attach function calls to foreign types.
trait RosenpassMaybeError {
    /// Checks whether something is an error or not
    fn to_rg_error(&self) -> Result<()>;
}

impl RosenpassMaybeError for oqs_sys::common::OQS_STATUS {
    fn to_rg_error(&self) -> Result<()> {
        use oqs_sys::common::OQS_STATUS;
        match self {
            OQS_STATUS::OQS_SUCCESS => Ok(()),
            OQS_STATUS::OQS_ERROR => Err(RosenpassError::Oqs),
            OQS_STATUS::OQS_EXTERNAL_LIB_ERROR_OPENSSL => Err(RosenpassError::OqsExternalLib),
        }
    }
}
