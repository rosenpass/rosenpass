//! Helpers for working with the zerocopy crate

use std::mem::size_of;

use zerocopy::{FromBytes, Ref};

use crate::RosenpassError;

/// Used to parse a network message using [zerocopy]
pub fn truncating_cast_into<T: FromBytes>(
    buf: &mut [u8],
) -> Result<Ref<&mut [u8], T>, RosenpassError> {
    Ref::new(&mut buf[..size_of::<T>()]).ok_or(RosenpassError::BufferSizeMismatch)
}

/// Used to parse a network message using [zerocopy], mutably
pub fn truncating_cast_into_nomut<T: FromBytes>(
    buf: &[u8],
) -> Result<Ref<&[u8], T>, RosenpassError> {
    Ref::new(&buf[..size_of::<T>()]).ok_or(RosenpassError::BufferSizeMismatch)
}
