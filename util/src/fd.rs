use std::os::fd::{OwnedFd, RawFd};

/// Clone some file descriptor
///
/// If the file descriptor is invalid, an error will be raised.
pub fn claim_fd(fd: RawFd) -> anyhow::Result<OwnedFd> {
    use rustix::{fd::BorrowedFd, io::dup};

    // This is safe since [dup] will simply raise
    let fd = unsafe { dup(BorrowedFd::borrow_raw(fd))? };
    Ok(fd)
}
