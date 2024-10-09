use mio::net::{UnixListener, UnixStream};
use std::os::fd::{OwnedFd, RawFd};

use crate::{
    fd::{claim_fd, claim_fd_inplace},
    result::OkExt,
};

pub mod interest {
    use mio::Interest;
    pub const R: Interest = Interest::READABLE;
    pub const W: Interest = Interest::WRITABLE;
    pub const RW: Interest = R.add(W);
}

pub trait UnixListenerExt: Sized {
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

pub trait UnixStreamExt: Sized {
    fn from_fd(fd: OwnedFd) -> anyhow::Result<Self>;
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self>;
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
