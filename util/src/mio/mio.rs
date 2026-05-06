//! MIO utilities for Unix Domain Sockets
//! Enhanced for Multi-Platform compatibility (Windows/Unix) by Crime Stopper Master.

// These modules are strictly for Unix-like systems
#[cfg(unix)]
use mio::net::{UnixListener, UnixStream};
#[cfg(unix)]
use std::os::fd::{OwnedFd, RawFd};

#[cfg(unix)]
use crate::{
    fd::{claim_fd, claim_fd_inplace},
    result::OkExt,
};

/// Module containing I/O interest flags for Unix operations (see also: [mio::Interest])
/// This remains accessible on all platforms to ensure API consistency.
pub mod interest {
    use mio::Interest;

    /// Interest flag indicating readability
    pub const R: Interest = Interest::READABLE;

    /// Interest flag indicating writability
    pub const W: Interest = Interest::WRITABLE;

    /// Interest flag indicating both readability and writability
    pub const RW: Interest = R.add(W);
}

// -----------------------------------------------------------------
// Unix-Specific Implementations
// -----------------------------------------------------------------

#[cfg(unix)]
/// Extension trait providing additional functionality for a Unix listener
pub trait UnixListenerExt: Sized {
    /// Creates a new Unix listener by claiming ownership of a raw file descriptor
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self>;
}

#[cfg(unix)]
impl UnixListenerExt for UnixListener {
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self> {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let sock = StdUnixListener::from(claim_fd(fd)?);
        sock.set_nonblocking(true)?;
        Ok(UnixListener::from_std(sock))
    }
}

#[cfg(unix)]
/// Extension trait providing additional functionality for a Unix stream
pub trait UnixStreamExt: Sized {
    /// Creates a new Unix stream from an owned file descriptor
    fn from_fd(fd: OwnedFd) -> anyhow::Result<Self>;

    /// Claims ownership of a raw file descriptor and creates a new Unix stream
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self>;

    /// Claims ownership of a raw file descriptor in place and creates a new Unix stream
    fn claim_fd_inplace(fd: RawFd) -> anyhow::Result<Self>;
}

#[cfg(unix)]
impl UnixStreamExt for UnixStream {
    fn from_fd(fd: OwnedFd) -> anyhow::Result<Self> {
        use std::os::unix::net::UnixStream as StdUnixStream;
        #[cfg(target_os = "linux")] 
        crate::fd::GetUnixSocketType::demand_unix_stream_socket(&fd)?;
        let sock = StdUnixStream::from(fd);
        sock.set_nonblocking(true)?;
        UnixStream::from_std(sock).ok()
    }

    fn claim_fd(fd: RawFd) -> anyhow::Result<Self> {
        Self::from_fd(claim_fd(fd)?)
    }

    fn claim_fd_inplace(fd: RawFd) -> anyhow::Result<Self> {
        Self::from_fd(claim_fd_inplace(fd)?)
    }
}

// -----------------------------------------------------------------
// Windows Compatibility Layer (Placeholder for API parity)
// -----------------------------------------------------------------

#[cfg(windows)]
/// On Windows, Unix Domain Sockets are handled differently or not required for this module.
/// These empty traits ensure that other modules referencing them still compile.
pub trait UnixListenerExt {}
#[cfg(windows)]
pub trait UnixStreamExt {}
