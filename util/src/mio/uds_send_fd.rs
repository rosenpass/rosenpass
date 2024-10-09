use std::os::fd::{AsFd, AsRawFd};
use std::{
    borrow::{Borrow, BorrowMut},
    cmp::min,
    collections::VecDeque,
    io::Write,
    marker::PhantomData,
};
use uds::UnixStreamExt as FdPassingExt;

use crate::{repeat, return_if};

pub struct WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    socket: BorrowSock,
    fds: BorrowFds,
    _sock_dummy: PhantomData<Sock>,
    _fd_dummy: PhantomData<Fd>,
}

impl<Sock, Fd, BorrowSock, BorrowFds> WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    pub fn new(socket: BorrowSock, fds: BorrowFds) -> Self {
        let _sock_dummy = PhantomData;
        let _fd_dummy = PhantomData;
        Self {
            socket,
            fds,
            _sock_dummy,
            _fd_dummy,
        }
    }

    pub fn into_parts(self) -> (BorrowSock, BorrowFds) {
        let Self { socket, fds, .. } = self;
        (socket, fds)
    }

    pub fn socket(&self) -> &Sock {
        self.socket.borrow()
    }

    pub fn fds(&self) -> &VecDeque<Fd> {
        self.fds.borrow()
    }

    pub fn fds_mut(&mut self) -> &mut VecDeque<Fd> {
        self.fds.borrow_mut()
    }
}

impl<Sock, Fd, BorrowSock, BorrowFds> WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: BorrowMut<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    pub fn socket_mut(&mut self) -> &mut Sock {
        self.socket.borrow_mut()
    }
}

impl<Sock, Fd, BorrowSock, BorrowFds> Write
    for WriteWithFileDescriptors<Sock, Fd, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    Fd: AsFd,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<Fd>>,
{
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // At least one byte of real data should be sent when sending ancillary data. -- unix(7)
        return_if!(buf.is_empty(), Ok(0));

        // The kernel constant SCM_MAX_FD defines a limit on the number of file descriptors
        // in the array.  Attempting to  send  an  array  larger  than  this  limit  causes
        // sendmsg(2)  to fail with the error EINVAL.  SCM_MAX_FD has the value 253 (or 255
        // before Linux 2.6.38).
        // -- unix(7)
        const SCM_MAX_FD: usize = 253;
        let buf = match self.fds().len() <= SCM_MAX_FD {
            false => &buf[..1], // Force caller to immediately call write() again to send its data
            true => buf,
        };

        // Allocate the buffer for the file descriptor array
        let fd_no = min(SCM_MAX_FD, self.fds().len());
        let mut fd_buf = [0; SCM_MAX_FD]; // My kingdom for alloca(3)
        let fd_buf = &mut fd_buf[..fd_no];

        // Fill the file descriptor array
        for (raw, fancy) in fd_buf.iter_mut().zip(self.fds().iter()) {
            *raw = fancy.as_fd().as_raw_fd();
        }

        // Send data and file descriptors
        let bytes_written = self.socket().send_fds(buf, fd_buf)?;

        // Drop the file descriptors from the Deque
        repeat!(fd_no, {
            self.fds_mut().pop_front();
        });

        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
