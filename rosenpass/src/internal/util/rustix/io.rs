//! Low level IO operations

use std::os::fd::{AsFd, AsRawFd};

use rustix::io::Errno;

use crate::internal::util::{convert::IntoTypeExt, rustix::SyscallResult};

/// Raw (pointer-based) access to the read(2) system call
///
/// This is a thin wrapper around [libc::read] with extra platform compatibility features
/// (such as honoring the maximum data transmission sizes for BSD)
///
/// # Safety
///
/// See [libc::read].
pub unsafe fn raw_read<Fd: AsFd>(fd: Fd, buf: *mut u8, len: usize) -> Result<usize, Errno> {
    // Darwin and some BSD configurations reject read counts above INT_MAX.
    let len = len.min(isize::MAX as usize).min(libc::c_int::MAX as usize);
    unsafe { libc::read(fd.as_fd().as_raw_fd(), buf.cast(), len) }
        .into_type::<SyscallResult<_>>()
        .claim_byte_count()
}
