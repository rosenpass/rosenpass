use mio::net::{UnixListener, UnixStream};
use rustix::fd::RawFd;

use crate::fd::claim_fd;

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
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self>;
}

impl UnixStreamExt for UnixStream {
    fn claim_fd(fd: RawFd) -> anyhow::Result<Self> {
        use std::os::unix::net::UnixStream as StdUnixStream;

        let sock = StdUnixStream::from(claim_fd(fd)?);
        sock.set_nonblocking(true)?;
        Ok(UnixStream::from_std(sock))
    }
}
