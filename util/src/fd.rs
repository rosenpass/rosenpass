use rustix::{
    fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    io::fcntl_dupfd_cloexec,
};

#[cfg(target_os = "linux")]
use rustix::io::DupFlags;

use crate::mem::Forgetting;

/// Prepare a file descriptor for use in Rust code.
///

/// Checks if the file descriptor is valid and duplicates it to a new file descriptor.
/// The old file descriptor is masked to avoid potential use after free (on file descriptor)
/// in case the given file descriptor is still used somewhere
pub fn claim_fd(fd: RawFd) -> rustix::io::Result<OwnedFd> {
    // check if valid fd
    if !(0..=i32::MAX).contains(&fd) {
        return Err(rustix::io::Errno::BADF);
    }

    let new = clone_fd_cloexec(unsafe { BorrowedFd::borrow_raw(fd) })?;
    mask_fd(fd)?;
    Ok(new)
}

pub fn mask_fd(fd: RawFd) -> rustix::io::Result<()> {
    // Safety: because the OwnedFd resulting from OwnedFd::from_raw_fd is wrapped in a Forgetting,
    // it never gets dropped, meaning that fd is never closed and thus outlives the OwnedFd
    let mut owned = Forgetting::new(unsafe { OwnedFd::from_raw_fd(fd) });
    clone_fd_to_cloexec(open_nullfd()?, &mut owned)
}

pub fn clone_fd_cloexec<Fd: AsFd>(fd: Fd) -> rustix::io::Result<OwnedFd> {
    const MINFD: RawFd = 3; // Avoid stdin, stdout, and stderr
    fcntl_dupfd_cloexec(fd, MINFD)
}

#[cfg(target_os = "linux")]
pub fn clone_fd_to_cloexec<Fd: AsFd>(fd: Fd, new: &mut OwnedFd) -> rustix::io::Result<()> {
    use rustix::io::dup3;
    dup3(fd, new, DupFlags::CLOEXEC)
}

#[cfg(not(target_os = "linux"))]
pub fn clone_fd_to_cloexec<Fd: AsFd>(fd: Fd, new: &mut OwnedFd) -> rustix::io::Result<()> {
    use rustix::io::{dup2, fcntl_setfd, FdFlags};
    dup2(&fd, new)?;
    fcntl_setfd(&new, FdFlags::CLOEXEC)
}

/// Open a "blocked" file descriptor. I.e. a file descriptor that is neither meant for reading nor
/// writing
pub fn open_nullfd() -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{open, Mode, OFlags};
    // TODO: Add tests showing that this will throw errors on use
    open("/dev/null", OFlags::CLOEXEC, Mode::empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::{read_to_string, File};
    use std::io::{Read, Write};
    use std::os::fd::IntoRawFd;
    use tempfile::tempdir;

    #[test]
    fn test_claim_fd() {
        let tmp_dir = tempdir().unwrap();
        let path = tmp_dir.path().join("test");
        let file = File::create(path.clone()).unwrap();
        let fd: RawFd = file.into_raw_fd();
        let owned_fd = claim_fd(fd).unwrap();
        let mut file = unsafe { File::from_raw_fd(owned_fd.into_raw_fd()) };
        file.write_all(b"Hello, World!").unwrap();

        let message = read_to_string(path).unwrap();
        assert_eq!(message, "Hello, World!");
    }

    #[test]
    fn test_claim_fd_invalid() {
        let fd: RawFd = -1;
        let result = claim_fd(fd);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Bad file descriptor (os error 9)"
        );
    }

    #[test]
    fn test_claim_fd_invalid_max() {
        let fd: RawFd = i64::MAX as RawFd;
        let result = claim_fd(fd);
        assert!(result.is_err());
        assert_eq!(
            result.unwrap_err().to_string(),
            "Bad file descriptor (os error 9)"
        );
    }

    #[test]
    fn test_open_nullfd_write() {
        let nullfd = open_nullfd().unwrap();
        let mut file = unsafe { File::from_raw_fd(nullfd.into_raw_fd()) };
        let res = file.write_all(b"Hello, World!");
        assert!(res.is_err());
        assert_eq!(
            res.unwrap_err().to_string(),
            "Bad file descriptor (os error 9)"
        );
    }

    #[test]
    fn test_open_nullfd_read() {
        let nullfd = open_nullfd().unwrap();
        let mut file = unsafe { File::from_raw_fd(nullfd.into_raw_fd()) };
        let mut buffer = [0; 10];
        let res = file.read_exact(&mut buffer);
        assert!(res.is_err());
        assert_eq!(res.unwrap_err().to_string(), "failed to fill whole buffer");
    }
}
