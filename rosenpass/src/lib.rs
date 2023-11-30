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
    #[error("buffer size mismatch, required {required_size} but found {actual_size}")]
    BufferSizeMismatch {
        required_size: usize,
        actual_size: usize,
    },
    #[error("invalid message type")]
    InvalidMessageType(u8),
}

impl RosenpassError {
    /// Helper function to check a buffer size
    fn check_buffer_size(required_size: usize, actual_size: usize) -> Result<(), Self> {
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
    fn to_rg_error(&self) -> Result<(), RosenpassError>;
}

impl RosenpassMaybeError for oqs_sys::common::OQS_STATUS {
    fn to_rg_error(&self) -> Result<(), RosenpassError> {
        use oqs_sys::common::OQS_STATUS;
        match self {
            OQS_STATUS::OQS_SUCCESS => Ok(()),
            OQS_STATUS::OQS_ERROR => Err(RosenpassError::Oqs),
            OQS_STATUS::OQS_EXTERNAL_LIB_ERROR_OPENSSL => Err(RosenpassError::OqsExternalLib),
        }
    }
}
