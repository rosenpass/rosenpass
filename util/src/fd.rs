use std::os::fd::{OwnedFd, RawFd};

/// Clone some file descriptor
///
/// If the file descriptor is invalid, an error will be raised.
pub fn claim_fd(fd: RawFd) -> anyhow::Result<OwnedFd> {
    use rustix::{fd::BorrowedFd, io::dup};

    // check if valid fd
    if !(0..=i32::MAX).contains(&fd) {
        return Err(anyhow::anyhow!("Invalid file descriptor"));
    }

    // This is safe since [dup] will simply raise an error on an invalid file descriptor
    let fd = unsafe { dup(BorrowedFd::borrow_raw(fd))? };
    Ok(fd)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::read_to_string;
    use std::fs::File;
    use std::io::Write;
    use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
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
        assert_eq!(result.unwrap_err().to_string(), "Invalid file descriptor");
    }

    #[test]
    fn test_claim_fd_invalid_max() {
        let fd: RawFd = i64::MAX as RawFd;
        let result = claim_fd(fd);
        assert!(result.is_err());
        assert_eq!(result.unwrap_err().to_string(), "Invalid file descriptor");
    }
}
