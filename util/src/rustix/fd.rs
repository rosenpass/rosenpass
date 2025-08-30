//! Basic utilities for working with file descriptors

use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use rustix::io::fcntl_dupfd_cloexec;

use super::IntoStdioErr;

use crate::mem::Forgetting;

/// Prepare a file descriptor for use in Rust code.
///
/// Checks if the file descriptor is valid and duplicates it to a new file descriptor.
/// The old file descriptor is masked to avoid potential use after free (on file descriptor)
/// in case the given file descriptor is still used somewhere
///
/// # Panic and safety
///
/// Will panic if the given file descriptor is negative of or larger than
/// the file descriptor numbers permitted by the operating system.
///
/// # Examples
///
/// ```
/// use std::io::Write;
/// use std::os::fd::{IntoRawFd, AsRawFd};
/// use tempfile::tempdir;
/// use rosenpass_util::rustix::{claim_fd, FdIo};
///
/// // Open a file and turn it into a raw file descriptor
/// let orig = tempfile::tempfile()?.into_raw_fd();
///
/// // Reclaim that file and ready it for reading
/// let mut claimed = FdIo(claim_fd(orig)?);
///
/// // A different file descriptor is used
/// assert!(orig.as_raw_fd() != claimed.0.as_raw_fd());
///
/// // Write some data
/// claimed.write_all(b"Hello, World!")?;
///
/// Ok::<(), std::io::Error>(())
/// ```
pub fn claim_fd(fd: RawFd) -> rustix::io::Result<OwnedFd> {
    let new = clone_fd_cloexec(unsafe { BorrowedFd::borrow_raw(fd) })?;
    mask_fd(fd)?;
    Ok(new)
}

/// Prepare a file descriptor for use in Rust code.
///
/// Checks if the file descriptor is valid.
///
/// Unlike [claim_fd], this will try to reuse the same file descriptor identifier instead of masking it.
///
/// # Panic and safety
///
/// Will panic if the given file descriptor is negative of or larger than
/// the file descriptor numbers permitted by the operating system.
///
/// # Examples
///
/// ```
/// use std::io::Write;
/// use std::os::fd::IntoRawFd;
/// use tempfile::tempdir;
/// use rosenpass_util::rustix::{claim_fd_inplace, FdIo};
///
/// // Open a file and turn it into a raw file descriptor
/// let fd = tempfile::tempfile()?.into_raw_fd();
///
/// // Reclaim that file and ready it for reading
/// let mut fd = FdIo(claim_fd_inplace(fd)?);
///
/// // Write some data
/// fd.write_all(b"Hello, World!")?;
///
/// Ok::<(), std::io::Error>(())
/// ```
pub fn claim_fd_inplace(fd: RawFd) -> rustix::io::Result<OwnedFd> {
    let mut new = unsafe { OwnedFd::from_raw_fd(fd) };
    let tmp = clone_fd_cloexec(&new)?;
    clone_fd_to_cloexec(tmp, &mut new)?;
    Ok(new)
}

/// Will close the given file descriptor and overwrite
/// it with a masking file descriptor (see [open_nullfd]) to prevent accidental reuse.
///
/// # Panic and safety
///
/// Will panic if the given file descriptor is negative of or larger than
/// the file descriptor numbers permitted by the operating system.
///
/// # Example
/// ```
/// # use std::fs::File;
/// # use std::io::Read;
/// # use std::os::unix::io::{AsRawFd, FromRawFd};
/// # use std::os::fd::IntoRawFd;
/// # use rustix::fd::AsFd;
/// # use rosenpass_util::rustix::mask_fd;
///
/// // Open a temporary file
/// let fd = tempfile::tempfile().unwrap().into_raw_fd();
/// assert!(fd >= 0);
///
/// // Mask the file descriptor
/// mask_fd(fd).unwrap();
///
/// // Verify the file descriptor now points to `/dev/null`
/// // Reading from `/dev/null` always returns 0 bytes
/// let mut replaced_file = unsafe { File::from_raw_fd(fd) };
/// let mut buffer = [0u8; 4];
/// let bytes_read = replaced_file.read(&mut buffer).unwrap();
/// assert_eq!(bytes_read, 0);
/// ```
pub fn mask_fd(fd: RawFd) -> rustix::io::Result<()> {
    // Safety: because the OwnedFd resulting from OwnedFd::from_raw_fd is wrapped in a Forgetting,
    // it never gets dropped, meaning that fd is never closed and thus outlives the OwnedFd
    let mut owned = Forgetting::new(unsafe { OwnedFd::from_raw_fd(fd) });
    clone_fd_to_cloexec(open_nullfd()?, &mut owned)
}

/// Duplicate a file descriptor, setting the close on exec flag
pub fn clone_fd_cloexec<Fd: AsFd>(fd: Fd) -> rustix::io::Result<OwnedFd> {
    /// Avoid stdin, stdout, and stderr
    const MINFD: RawFd = 3;
    fcntl_dupfd_cloexec(fd, MINFD)
}

/// Duplicate a file descriptor, setting the close on exec flag.
///
/// This is slightly different from [clone_fd_cloexec], as this function supports specifying an
/// explicit destination file descriptor.
#[cfg(target_os = "linux")]
pub fn clone_fd_to_cloexec<Fd: AsFd>(fd: Fd, new: &mut OwnedFd) -> rustix::io::Result<()> {
    use rustix::io::{dup3, DupFlags};
    dup3(fd, new, DupFlags::CLOEXEC)
}

#[cfg(not(target_os = "linux"))]
/// Duplicate a file descriptor, setting the close on exec flag.
///
/// This is slightly different from [clone_fd_cloexec], as this function supports specifying an
/// explicit destination file descriptor.
pub fn clone_fd_to_cloexec<Fd: AsFd>(fd: Fd, new: &mut OwnedFd) -> rustix::io::Result<()> {
    use rustix::io::{dup2, fcntl_setfd, FdFlags};
    dup2(&fd, new)?;
    fcntl_setfd(&new, FdFlags::CLOEXEC)
}

/// Open a "blocked" file descriptor. I.e. a file descriptor that is neither meant for reading nor
/// writing.
///
/// # Safety
///
/// The behavior of the file descriptor when being written to or from is undefined.
///
/// # Examples
///
/// ```
/// use std::{fs::File, io::Write, os::fd::IntoRawFd};
/// use rustix::fd::FromRawFd;
/// use rosenpass_util::rustix::open_nullfd;
///
/// let nullfd = open_nullfd().unwrap();
/// ```
pub fn open_nullfd() -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{open, Mode, OFlags};
    // TODO: Add tests showing that this will throw errors on use
    open("/dev/null", OFlags::CLOEXEC, Mode::empty())
}

/// Read and write directly from a file descriptor
///
/// # Examples
///
/// See [claim_fd].
pub struct FdIo<Fd: AsFd>(pub Fd);

impl<Fd: AsFd> std::io::Read for FdIo<Fd> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        rustix::io::read(&self.0, buf).into_stdio_err()
    }
}

impl<Fd: AsFd> std::io::Write for FdIo<Fd> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        rustix::io::write(&self.0, buf).into_stdio_err()
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    #[test]
    #[should_panic]
    fn test_claim_fd_invalid_neg() {
        let _ = claim_fd(-1);
    }

    #[test]
    #[should_panic]
    fn test_claim_fd_invalid_max() {
        let _ = claim_fd(i64::MAX as RawFd);
    }

    #[test]
    #[should_panic]
    fn test_claim_fd_inplace_invalid_neg() {
        let _ = claim_fd_inplace(-1);
    }

    #[test]
    #[should_panic]
    fn test_claim_fd_inplace_invalid_max() {
        let _ = claim_fd_inplace(i64::MAX as RawFd);
    }

    #[test]
    #[should_panic]
    fn test_mask_fd_invalid_neg() {
        let _ = mask_fd(-1);
    }

    #[test]
    #[should_panic]
    fn test_mask_fd_invalid_max() {
        let _ = mask_fd(i64::MAX as RawFd);
    }

    #[test]
    fn test_open_nullfd() -> anyhow::Result<()> {
        let mut file = FdIo(open_nullfd()?);
        let mut buf = [0; 10];
        assert!(matches!(file.read(&mut buf), Ok(0) | Err(_)));
        assert!(file.write(&buf).is_err());
        Ok(())
    }

    #[test]
    fn test_nullfd_read_write() {
        let nullfd = open_nullfd().unwrap();
        let mut buf = vec![0u8; 16];
        assert_eq!(rustix::io::read(&nullfd, &mut buf).unwrap(), 0);
        assert!(rustix::io::write(&nullfd, b"test").is_err());
    }
}
