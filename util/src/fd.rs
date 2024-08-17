use anyhow::bail;
use rustix::{
    fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd},
    io::fcntl_dupfd_cloexec,
};

use crate::{mem::Forgetting, result::OkExt};

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

/// Prepare a file descriptor for use in Rust code.
///
/// Checks if the file descriptor is valid.
///
/// Unlike [claim_fd], this will reuse the same file descriptor identifier instead of masking it.
pub fn claim_fd_inplace(fd: RawFd) -> rustix::io::Result<OwnedFd> {
    let mut new = unsafe { OwnedFd::from_raw_fd(fd) };
    let tmp = clone_fd_cloexec(&new)?;
    clone_fd_to_cloexec(tmp, &mut new)?;
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
    use rustix::io::{dup3, DupFlags};
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

/// Convert low level errors into std::io::Error
pub trait IntoStdioErr {
    type Target;
    fn into_stdio_err(self) -> Self::Target;
}

impl IntoStdioErr for rustix::io::Errno {
    type Target = std::io::Error;

    fn into_stdio_err(self) -> Self::Target {
        std::io::Error::from_raw_os_error(self.raw_os_error())
    }
}

impl<T> IntoStdioErr for rustix::io::Result<T> {
    type Target = std::io::Result<T>;

    fn into_stdio_err(self) -> Self::Target {
        self.map_err(IntoStdioErr::into_stdio_err)
    }
}

/// Read and write directly from a file descriptor
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

pub trait StatExt {
    fn is_socket(&self) -> bool;
}

impl StatExt for rustix::fs::Stat {
    fn is_socket(&self) -> bool {
        use rustix::fs::FileType;
        let ft = FileType::from_raw_mode(self.st_mode);
        matches!(ft, FileType::Socket)
    }
}

pub trait TryStatExt {
    type Error;
    fn is_socket(&self) -> Result<bool, Self::Error>;
}

impl<T> TryStatExt for T
where
    T: AsFd,
{
    type Error = rustix::io::Errno;

    fn is_socket(&self) -> Result<bool, Self::Error> {
        rustix::fs::fstat(self)?.is_socket().ok()
    }
}

pub trait GetSocketType {
    type Error;
    fn socket_type(&self) -> Result<rustix::net::SocketType, Self::Error>;
    fn is_datagram_socket(&self) -> Result<bool, Self::Error> {
        use rustix::net::SocketType;
        matches!(self.socket_type()?, SocketType::DGRAM).ok()
    }
    fn is_stream_socket(&self) -> Result<bool, Self::Error> {
        Ok(self.socket_type()? == rustix::net::SocketType::STREAM)
    }
}

impl<T> GetSocketType for T
where
    T: AsFd,
{
    type Error = rustix::io::Errno;

    fn socket_type(&self) -> Result<rustix::net::SocketType, Self::Error> {
        rustix::net::sockopt::get_socket_type(self)
    }
}

#[cfg(target_os = "linux")]
pub trait GetSocketDomain {
    type Error;
    fn socket_domain(&self) -> Result<rustix::net::AddressFamily, Self::Error>;
    fn socket_address_family(&self) -> Result<rustix::net::AddressFamily, Self::Error> {
        self.socket_domain()
    }
    fn is_unix_socket(&self) -> Result<bool, Self::Error> {
        Ok(self.socket_domain()? == rustix::net::AddressFamily::UNIX)
    }
}

#[cfg(target_os = "linux")]
impl<T> GetSocketDomain for T
where
    T: AsFd,
{
    type Error = rustix::io::Errno;

    fn socket_domain(&self) -> Result<rustix::net::AddressFamily, Self::Error> {
        rustix::net::sockopt::get_socket_domain(self)
    }
}

#[cfg(target_os = "linux")]
pub trait GetUnixSocketType {
    type Error;
    fn is_unix_stream_socket(&self) -> Result<bool, Self::Error>;
    fn demand_unix_stream_socket(&self) -> anyhow::Result<()>;
}

#[cfg(target_os = "linux")]
impl<T> GetUnixSocketType for T
where
    T: GetSocketType + GetSocketDomain<Error = <T as GetSocketType>::Error>,
    anyhow::Error: From<<T as GetSocketType>::Error>,
{
    type Error = <T as GetSocketType>::Error;

    fn is_unix_stream_socket(&self) -> Result<bool, Self::Error> {
        Ok(self.is_unix_socket()? && self.is_stream_socket()?)
    }

    fn demand_unix_stream_socket(&self) -> anyhow::Result<()> {
        use rustix::net::AddressFamily as SA;
        use rustix::net::SocketType as ST;
        match (self.socket_domain()?, self.socket_type()?) {
            (SA::UNIX, ST::STREAM) => Ok(()),
            (SA::UNIX, mode) => bail!("Expected unix socket in stream mode, but mode is {mode:?}"),
            (domain, _) => bail!("Expected unix socket, but socket domain is {domain:?} instead"),
        }
    }
}

#[cfg(target_os = "linux")]
pub trait GetSocketProtocol {
    fn socket_protocol(&self) -> Result<Option<rustix::net::Protocol>, rustix::io::Errno>;
    fn is_udp_socket(&self) -> Result<bool, rustix::io::Errno> {
        self.socket_protocol()?
            .map(|p| p == rustix::net::ipproto::UDP)
            .unwrap_or(false)
            .ok()
    }
    fn demand_udp_socket(&self) -> anyhow::Result<()> {
        match self.socket_protocol() {
            Ok(Some(rustix::net::ipproto::UDP)) => Ok(()),
            Ok(Some(other_proto)) => {
                bail!("Not a udp socket, instead socket protocol is: {other_proto:?}")
            }
            Ok(None) => bail!("getsockopt() returned empty value"),
            Err(errno) => Err(errno.into_stdio_err())?,
        }
    }
}

#[cfg(target_os = "linux")]
impl<T> GetSocketProtocol for T
where
    T: AsFd,
{
    fn socket_protocol(&self) -> Result<Option<rustix::net::Protocol>, rustix::io::Errno> {
        rustix::net::sockopt::get_socket_protocol(self)
    }
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
