use mio::net::{UnixListener, UnixStream};
use std::os::fd::{OwnedFd, RawFd};

use crate::{
    fd::{claim_fd, claim_fd_inplace},
    result::OkExt,
};

/// Module containing I/O interest flags for Unix operations (see also: [mio::Interest])
pub mod interest {
    use mio::Interest;

    /// Interest flag indicating readability
    pub const R: Interest = Interest::READABLE;

    /// Interest flag indicating writability
    pub const W: Interest = Interest::WRITABLE;

    /// Interest flag indicating both readability and writability
    pub const RW: Interest = R.add(W);
}

/// Extension trait providing additional functionality for Unix listener
pub trait UnixListenerExt: Sized {
    /// Creates a new Unix listener by claiming ownership of a raw file descriptor
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self>;
}

impl UnixListenerExt for UnixListener {
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self> {
        use std::os::unix::net::UnixListener as StdUnixListener;

        let sock = StdUnixListener::from(claim_fd(fd)?);
        sock.set_nonblocking(true)?;
        Ok(UnixListener::from_std(sock))
    }
}

/// Extension trait providing additional functionality for Unix streams
pub trait UnixStreamExt: Sized {
    /// Creates a new Unix stream from an owned file descriptor
    fn from_fd(fd: OwnedFd) -> anyhow::Result<Self>;

    /// Claims ownership of a raw file descriptor and creates a new Unix stream
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self>;

    /// Claims ownership of a raw file descriptor in place and creates a new Unix stream
    fn claim_fd_inplace(fd: RawFd) -> anyhow::Result<Self>;
}

impl UnixStreamExt for UnixStream {
    fn from_fd(fd: OwnedFd) -> anyhow::Result<Self> {
        use std::os::unix::net::UnixStream as StdUnixStream;
        #[cfg(target_os = "linux")] // TODO: We should support this on other plattforms
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
