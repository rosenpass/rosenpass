use libsodium_sys as libsodium;

// Add these imports for log and thiserror
use log::{error, trace};
use thiserror::Error;

// Custom error type for libsodium operations
#[derive(Error, Debug)]
enum SodiumError {
    #[error("Error in libsodium's {0}.")]
    LibSodiumError(#[from] libsodium::libsodium_errno_t),
}

macro_rules! sodium_call {
    ($name:ident, $($args:expr),*) => {
        ::rosenpass_util::attempt!({
            if unsafe { libsodium::$name($($args),*) } <= -1 {
                let errno = libsodium::sodium_errno();
                error!("Error in libsodium's {}.", stringify!($name));
                return Err(SodiumError::LibSodiumError(errno));
            }
            Ok(())
        })
    };
    ($name:ident) => { sodium_call!($name, ) };
}

#[inline]
pub fn init() -> Result<(), SodiumError> {
    trace!("initializing libsodium");
    sodium_call!(sodium_init)
}

pub mod aead;
pub mod hash;
pub mod helpers;