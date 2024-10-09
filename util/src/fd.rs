//! Utilities for working with file descriptors

use anyhow::bail;
use rustix::io::fcntl_dupfd_cloexec;
use std::os::fd::{AsFd, BorrowedFd, FromRawFd, OwnedFd, RawFd};

use crate::{mem::Forgetting, result::OkExt};

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
/// use rosenpass_util::fd::{claim_fd, FdIo};
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
/// use rosenpass_util::fd::{claim_fd_inplace, FdIo};
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
/// use rosenpass_util::fd::open_nullfd;
///
/// let nullfd = open_nullfd().unwrap();
/// ```
pub fn open_nullfd() -> rustix::io::Result<OwnedFd> {
    use rustix::fs::{open, Mode, OFlags};
    // TODO: Add tests showing that this will throw errors on use
    open("/dev/null", OFlags::CLOEXEC, Mode::empty())
}

/// Convert low level errors into std::io::Error
///
/// # Examples
///
/// ```
/// use std::io::ErrorKind as EK;
/// use rustix::io::Errno;
/// use rosenpass_util::fd::IntoStdioErr;
///
/// let e = Errno::INTR.into_stdio_err();
/// assert!(matches!(e.kind(), EK::Interrupted));
///
/// let r : rustix::io::Result<()> = Err(Errno::INTR);
/// assert!(matches!(r, Err(e) if e.kind() == EK::Interrupted));
/// ```
pub trait IntoStdioErr {
    /// Target type produced (e.g. std::io:Error or std::io::Result depending on context
    type Target;
    /// Convert low level errors to
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

/// Helpers for accessing stat(2) information
pub trait StatExt {
    /// Check if the file is a socket
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::fd::StatExt;
    /// assert!(rustix::fs::stat("/")?.is_socket() == false);
    /// Ok::<(), rustix::io::Errno>(())
    /// ````
    fn is_socket(&self) -> bool;
}

impl StatExt for rustix::fs::Stat {
    fn is_socket(&self) -> bool {
        use rustix::fs::FileType;
        let ft = FileType::from_raw_mode(self.st_mode);
        matches!(ft, FileType::Socket)
    }
}

/// Helpers for accessing stat(2) information on an open file descriptor
pub trait TryStatExt {
    /// Error type returned by operations
    type Error;

    /// Check if the file is a socket
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::fd::TryStatExt;
    /// let fd = rustix::fs::open("/", rustix::fs::OFlags::empty(), rustix::fs::Mode::empty())?;
    /// assert!(matches!(fd.is_socket(), Ok(false)));
    /// Ok::<(), rustix::io::Errno>(())
    /// ````
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

/// Determine the type of socket a file descriptor represents
pub trait GetSocketType {
    /// Error type returned by operations in this trait
    type Error;
    /// Look up the socket; see [rustix::net::sockopt::get_socket_type]
    fn socket_type(&self) -> Result<rustix::net::SocketType, Self::Error>;
    /// Checks if the socket is a datagram socket
    fn is_datagram_socket(&self) -> Result<bool, Self::Error> {
        use rustix::net::SocketType;
        matches!(self.socket_type()?, SocketType::DGRAM).ok()
    }
    /// Checks if the socket is a stream socket
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

/// Distinguish different socket address familys; e.g. IP and unix sockets
#[cfg(target_os = "linux")]
pub trait GetSocketDomain {
    /// Error type returned by operations in this trait
    type Error;
    /// Retrieve the socket domain (address family)
    fn socket_domain(&self) -> Result<rustix::net::AddressFamily, Self::Error>;
    /// Alias for [socket_domain]
    fn socket_address_family(&self) -> Result<rustix::net::AddressFamily, Self::Error> {
        self.socket_domain()
    }
    /// Check if the underlying socket is a unix domain socket
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

/// Distinguish different types of unix sockets
#[cfg(target_os = "linux")]
pub trait GetUnixSocketType {
    /// Error type returned by operations in this trait
    type Error;
    /// Check if the socket is a unix stream socket
    fn is_unix_stream_socket(&self) -> Result<bool, Self::Error>;
    /// Returns Ok(()) only if the underlying socket is a unix stream socket
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
/// Distinguish between different network socket protocols (e.g. tcp, udp)
pub trait GetSocketProtocol {
    /// Retrieve the socket protocol
    fn socket_protocol(&self) -> Result<Option<rustix::net::Protocol>, rustix::io::Errno>;
    /// Check if the socket is a udp socket
    fn is_udp_socket(&self) -> Result<bool, rustix::io::Errno> {
        self.socket_protocol()?
            .map(|p| p == rustix::net::ipproto::UDP)
            .unwrap_or(false)
            .ok()
    }
    /// Return Ok(()) only if the socket is a udp socket
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
    use std::io::{Read, Write};

    #[test]
    #[should_panic(expected = "fd != u32::MAX as RawFd")]
    fn test_claim_fd_invalid_neg() {
        let _ = claim_fd(-1);
    }

    #[test]
    #[should_panic(expected = "fd != u32::MAX as RawFd")]
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
        assert!(matches!(file.write(&buf), Err(_)));
        Ok(())
    }
}
