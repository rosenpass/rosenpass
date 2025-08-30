//! Rustix extensions for getting information about file descriptors`

use std::os::fd::AsFd;

use anyhow::bail;

use super::IntoStdioErr;

use crate::result::OkExt;

/// Helpers for accessing stat(2) information
pub trait StatExt {
    /// Check if the file is a socket
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::rustix::StatExt;
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
    /// use rosenpass_util::rustix::TryStatExt;
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

/// Distinguish different socket address families; e.g. IP and unix sockets
#[cfg(target_os = "linux")]
pub trait GetSocketDomain {
    /// Error type returned by operations in this trait
    type Error;
    /// Retrieve the socket domain (address family)
    fn socket_domain(&self) -> Result<rustix::net::AddressFamily, Self::Error>;
    /// Alias for [Self::socket_domain]
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

    /// Checks whether the socket is a Unix stream socket.
    ///
    /// # Returns
    /// - `Ok(true)` if the socket is a Unix stream socket.
    /// - `Ok(false)` if the socket is not a Unix stream socket.
    /// - `Err(Self::Error)` if there is an error while performing the check.
    ///
    /// # Examples
    /// ```
    /// # use std::fs::File;
    /// # use std::os::fd::{AsFd, BorrowedFd};
    /// # use std::os::unix::net::UnixListener;
    /// # use tempfile::NamedTempFile;
    /// # use rosenpass_util::rustix::GetUnixSocketType;
    /// let f = {
    ///     // Generate a temp file and take its path
    ///     // Remove the temp file
    ///     // Create a unix socket on the temp path that is not unused
    ///     let temp_file = NamedTempFile::new().unwrap();
    ///     let socket_path = temp_file.path().to_owned();
    ///     std::fs::remove_file(&socket_path).unwrap();
    ///     UnixListener::bind(socket_path).unwrap()
    /// };
    /// assert!(matches!(f.as_fd().is_unix_stream_socket(), Ok(true)));
    /// ```
    fn is_unix_stream_socket(&self) -> Result<bool, Self::Error>;
    /// Returns Ok(()) only if the underlying socket is a unix stream socket
    /// # Examples
    /// ```
    /// # use std::fs::File;
    /// # use std::os::fd::{AsFd, BorrowedFd};
    /// # use std::os::unix::net::{UnixDatagram, UnixListener};
    /// # use tempfile::NamedTempFile;
    /// # use rosenpass_util::rustix::GetUnixSocketType;
    /// let f = {
    ///     // Generate a temp file and take its path
    ///     // Remove the temp file
    ///     // Create a unix socket on the temp path that is not unused
    ///     let temp_file = NamedTempFile::new().unwrap();
    ///     let socket_path = temp_file.path().to_owned();
    ///     std::fs::remove_file(&socket_path).unwrap();
    ///     UnixListener::bind(socket_path).unwrap()
    /// };
    /// assert!(matches!(f.as_fd().demand_unix_stream_socket(), Ok(())));
    /// // Error if the FD is a file
    /// let temp_file = NamedTempFile::new().unwrap();
    /// assert_eq!(temp_file.as_fd().demand_unix_stream_socket().err().unwrap().to_string(),
    ///  "Socket operation on non-socket (os error 88)"
    /// );
    /// // Error if the FD is a Unix stream with a wrong mode (e.g. Datagram)
    /// let f = {
    ///     let temp_file = NamedTempFile::new().unwrap();
    ///     let socket_path = temp_file.path().to_owned();
    ///     std::fs::remove_file(&socket_path).unwrap();
    ///     UnixDatagram::bind(socket_path).unwrap()
    /// };
    /// assert_eq!(f.as_fd().demand_unix_stream_socket().err().unwrap().to_string(),
    ///  "Expected unix socket in stream mode, but mode is SocketType(2)"
    /// );
    /// ```
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
    /// Retrieves the socket's protocol.
    ///
    /// # Returns
    /// - `Ok(Some(Protocol))`: The protocol of the socket if available.
    /// - `Ok(None)`: If the protocol information is unavailable.
    /// - `Err(rustix::io::Errno)`: If an error occurs while retrieving the protocol.
    ///
    /// # Examples
    /// ```
    /// # use std::net::UdpSocket;
    /// # use std::os::fd::{AsFd, AsRawFd};
    /// # use rosenpass_util::rustix::GetSocketProtocol;
    /// let socket = UdpSocket::bind("127.0.0.1:0")?;
    /// assert_eq!(socket.as_fd().socket_protocol().unwrap().unwrap(), rustix::net::ipproto::UDP);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    fn socket_protocol(&self) -> Result<Option<rustix::net::Protocol>, rustix::io::Errno>;
    /// Check if the socket is a udp socket
    ///
    /// # Examples
    /// ```
    /// # use std::net::UdpSocket;
    /// # use std::net::TcpListener;
    /// # use std::os::fd::{AsFd, AsRawFd};
    /// # use rosenpass_util::rustix::GetSocketProtocol;
    /// let socket = UdpSocket::bind("127.0.0.1:0")?;
    /// assert!(socket.as_fd().is_udp_socket().unwrap());
    ///
    /// let socket = TcpListener::bind("127.0.0.1:0")?;
    /// assert!(!socket.as_fd().is_udp_socket().unwrap());
    /// # Ok::<(), std::io::Error>(())
    /// ```
    fn is_udp_socket(&self) -> Result<bool, rustix::io::Errno> {
        self.socket_protocol()?
            .map(|p| p == rustix::net::ipproto::UDP)
            .unwrap_or(false)
            .ok()
    }

    /// Ensures that the socket is a UDP socket, returning an error otherwise.
    ///
    /// # Returns
    /// - `Ok(())` if the socket is a UDP socket.
    /// - `Err(anyhow::Error)` if the socket is not a UDP socket or if an error occurs retrieving the socket protocol.
    ///
    /// # Examples
    /// ```
    /// # use std::net::UdpSocket;
    /// # use std::net::TcpListener;
    /// # use std::os::fd::{AsFd, AsRawFd};
    /// # use rosenpass_util::rustix::GetSocketProtocol;
    /// let socket = UdpSocket::bind("127.0.0.1:0")?;
    /// assert!(matches!(socket.as_fd().demand_udp_socket(), Ok(())));
    ///
    /// let socket = TcpListener::bind("127.0.0.1:0")?;
    /// assert_eq!(socket.as_fd().demand_udp_socket().unwrap_err().to_string(),
    ///     "Not a udp socket, instead socket protocol is: Protocol(6)");
    /// # Ok::<(), std::io::Error>(())
    /// ```
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

