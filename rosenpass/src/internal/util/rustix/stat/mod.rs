use std::os::fd::AsFd;

use crate::internal::util::result::OkExt;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "linux")]
pub use linux::*;

/// Helpers for accessing stat(2) information
pub trait StatExt {
    /// Check if the file is a socket
    ///
    /// # Examples
    ///
    #[cfg_attr(feature = "expose_internal_modules", doc = "```")]
    #[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
    /// use rosenpass::internal::util::rustix::StatExt;
    /// assert!(rustix::fs::stat("/")?.is_socket() == false);
    /// Ok::<(), rustix::io::Errno>(())
    /// ````
    fn is_socket(&self) -> bool;

    /// Access to the size of a file
    fn size(&self) -> i64;
}

impl StatExt for rustix::fs::Stat {
    fn is_socket(&self) -> bool {
        use rustix::fs::FileType;
        let ft = FileType::from_raw_mode(self.st_mode);
        matches!(ft, FileType::Socket)
    }

    fn size(&self) -> i64 {
        self.st_size
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
    #[cfg_attr(feature = "expose_internal_modules", doc = "```")]
    #[cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
    /// use rosenpass::internal::util::rustix::TryStatExt;
    /// let fd = rustix::fs::open("/", rustix::fs::OFlags::empty(), rustix::fs::Mode::empty())?;
    /// assert!(matches!(fd.is_socket(), Ok(false)));
    /// Ok::<(), rustix::io::Errno>(())
    /// ````
    fn is_socket(&self) -> Result<bool, Self::Error>;

    /// Access the size of the file
    fn size(&self) -> Result<i64, Self::Error>;
}

impl<T> TryStatExt for T
where
    T: AsFd,
{
    type Error = rustix::io::Errno;

    fn is_socket(&self) -> Result<bool, Self::Error> {
        rustix::fs::fstat(self)?.is_socket().ok()
    }

    fn size(&self) -> Result<i64, Self::Error> {
        rustix::fs::fstat(self)?.size().ok()
    }
}

/// Helpers for accessing statfs(2) information
///
/// This extension uses Linux's filesystem type identifier for secretmem.
pub trait StatFsExt {
    /// Determine whether the underlying file descriptor that generated this [rustix::fs::StatFs]
    /// is a memfd_secret(2) file descriptor
    fn is_memfd_secret(&self) -> bool;
}

impl StatFsExt for rustix::fs::StatFs {
    fn is_memfd_secret(&self) -> bool {
        cfg_select! {
            target_os = "linux" => {
                const SECRETMEM_MAGIC: rustix::fs::FsWord = 0x5345_434d;
                self.f_type == SECRETMEM_MAGIC
            },
            _ => false,
        }
    }
}

/// Helpers for accessing stat(2) information on an open file descriptor
pub trait TryStatFsExt {
    /// Error type returned by operations
    type Error;

    /// Determine whether the underlying file descriptor is a memfd_secret(2) file descriptor
    ///
    /// memfd_secret(2) only exists on Linux; on other operating systems this
    /// always returns `Ok(false)` without querying the kernel
    fn is_memfd_secret(&self) -> Result<bool, Self::Error>;
}

impl<T> TryStatFsExt for T
where
    T: AsFd,
{
    type Error = rustix::io::Errno;

    fn is_memfd_secret(&self) -> Result<bool, Self::Error> {
        cfg_select! {
            target_os = "linux" => rustix::fs::fstatfs(self)?.is_memfd_secret().ok(),
            _ => Ok(false),
        }
    }
}

/// Determine the type of socket a file descriptor represents
pub trait GetSocketType {
    /// Error type returned by operations in this trait
    type Error;
    /// Look up the socket; see `rustix::net::sockopt::getsockopt(fd, SOL_SOCKET, SO_TYPE)`
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
        rustix::net::sockopt::socket_type(self)
    }
}
