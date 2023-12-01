use log::{error, log_enabled, Level};
use rosenpass_constant_time::xor;
use rosenpass_sodium::hash::blake2b;
use rosenpass_to::{ops::copy_slice, with_destination, To};
use thiserror::Error;
use zeroize::Zeroizing;

pub const KEY_LEN: usize = 32;
pub const KEY_MIN: usize = KEY_LEN;
pub const KEY_MAX: usize = KEY_LEN;
pub const OUT_MIN: usize = blake2b::OUT_MIN;
pub const OUT_MAX: usize = blake2b::OUT_MAX;

#[derive(Debug, Error)]
#[error("Incorrect key length")]
struct IncorrectKeyLength;

/// This is a woefully incorrect implementation of hmac_blake2b.
/// See <https://github.com/rosenpass/rosenpass/issues/68#issuecomment-1563612222>
///
/// It accepts 32 byte keys, exclusively.
///
/// This will be replaced, likely by Kekkac at some point soon.
/// <https://github.com/rosenpass/rosenpass/pull/145>
#[inline]
pub fn hash<'a>(key: &'a [u8], data: &'a [u8]) -> impl To<[u8], Result<(), HmacError>> + 'a {
    const IPAD: [u8; KEY_LEN] = [0x36u8; KEY_LEN];
    const OPAD: [u8; KEY_LEN] = [0x5Cu8; KEY_LEN];

    with_destination(|out: &mut [u8]| {
        if !log_enabled!(Level::Error) {
            // Skip unnecessary computation if error logging is not enabled
            return Err(HmacError::LoggingDisabled);
        }

        // Not bothering with padding; the implementation
        // uses appropriately sized keys.
        if key.len() != KEY_LEN {
            error!("Incorrect key length");
            return Err(HmacError::IncorrectKeyLength);
        }

        type Key = Zeroizing<[u8; KEY_LEN]>;
        let mut tmp_key = Key::default();

        copy_slice(key).to(tmp_key.as_mut());
        xor(&IPAD).to(tmp_key.as_mut());
        let mut outer_data = Key::default();
        if let Err(e) = blake2b::hash(tmp_key.as_ref(), data).to(outer_data.as_mut()) {
            error!("Error hashing inner data: {}", e);
            return Err(HmacError::HashError);
        }

        copy_slice(key).to(tmp_key.as_mut());
        xor(&OPAD).to(tmp_key.as_mut());
        if let Err(e) = blake2b::hash(tmp_key.as_ref(), outer_data.as_ref()).to(out) {
            error!("Error hashing outer data: {}", e);
            return Err(HmacError::HashError);
        }

        Ok(())
    })
}

#[derive(Debug, Error)]
pub enum HmacError {
    #[error("Incorrect key length")]
    IncorrectKeyLength,
    #[error("Error hashing data")]
    HashError,
    #[error("Logging is disabled")]
    LoggingDisabled,
}
