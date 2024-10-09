use std::{
    borrow::{Borrow, BorrowMut},
    collections::VecDeque,
    io::Read,
    marker::PhantomData,
    os::fd::{FromRawFd, OwnedFd},
};
use uds::UnixStreamExt as FdPassingExt;

use crate::fd::{claim_fd_inplace, IntoStdioErr};

pub struct ReadWithFileDescriptors<const MAX_FDS: usize, Sock, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<OwnedFd>>,
{
    socket: BorrowSock,
    fds: BorrowFds,
    _sock_dummy: PhantomData<Sock>,
}

impl<const MAX_FDS: usize, Sock, BorrowSock, BorrowFds>
    ReadWithFileDescriptors<MAX_FDS, Sock, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<OwnedFd>>,
{
    pub fn new(socket: BorrowSock, fds: BorrowFds) -> Self {
        let _sock_dummy = PhantomData;
        Self {
            socket,
            fds,
            _sock_dummy,
        }
    }

    pub fn into_parts(self) -> (BorrowSock, BorrowFds) {
        let Self { socket, fds, .. } = self;
        (socket, fds)
    }

    pub fn socket(&self) -> &Sock {
        self.socket.borrow()
    }

    pub fn fds(&self) -> &VecDeque<OwnedFd> {
        self.fds.borrow()
    }

    pub fn fds_mut(&mut self) -> &mut VecDeque<OwnedFd> {
        self.fds.borrow_mut()
    }
}

impl<const MAX_FDS: usize, Sock, BorrowSock, BorrowFds>
    ReadWithFileDescriptors<MAX_FDS, Sock, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    BorrowSock: BorrowMut<Sock>,
    BorrowFds: BorrowMut<VecDeque<OwnedFd>>,
{
    pub fn socket_mut(&mut self) -> &mut Sock {
        self.socket.borrow_mut()
    }
}

impl<const MAX_FDS: usize, Sock, BorrowSock, BorrowFds> Read
    for ReadWithFileDescriptors<MAX_FDS, Sock, BorrowSock, BorrowFds>
where
    Sock: FdPassingExt,
    BorrowSock: Borrow<Sock>,
    BorrowFds: BorrowMut<VecDeque<OwnedFd>>,
{
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Calculate space for additional file descriptors
        let have_fds_before_read = self.fds().len();
        let free_fd_slots = MAX_FDS.saturating_sub(have_fds_before_read);

        // Allocate a buffer for file descriptors
        let mut fd_buf = [0; MAX_FDS];
        let fd_buf = &mut fd_buf[..free_fd_slots];

        // Read from the unix socket
        let (bytes_read, fds_read) = self.socket.borrow().recv_fds(buf, fd_buf)?;
        let fd_buf = &fd_buf[..fds_read];

        // Process the file descriptors
        let mut fd_iter = fd_buf.iter();

        // Try claiming all the file descriptors
        let mut claim_fd_result = Ok(bytes_read);
        self.fds_mut().reserve(fd_buf.len());
        for fd in fd_iter.by_ref() {
            match claim_fd_inplace(*fd) {
                Ok(owned) => self.fds_mut().push_back(owned),
                Err(e) => {
                    // Abort on error and pass to error handler
                    // Note that claim_fd_inplace is responsible for closing this particular
                    // file descriptor if claiming it fails
                    claim_fd_result = Err(e.into_stdio_err());
                    break;
                }
            }
        }

        // Return if we where able to claim all file descriptors
        if claim_fd_result.is_ok() {
            return claim_fd_result;
        };

        // An error occurred while claiming fds
        self.fds_mut().truncate(have_fds_before_read); // Close fds successfully claimed

        // Close the remaining fds
        for fd in fd_iter {
            unsafe { drop(OwnedFd::from_raw_fd(*fd)) };
        }

        claim_fd_result
    }
}
