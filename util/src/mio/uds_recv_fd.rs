use std::{
    borrow::{Borrow, BorrowMut},
    collections::VecDeque,
    io::Read,
    marker::PhantomData,
    os::fd::{FromRawFd, OwnedFd},
};
use uds::UnixStreamExt as FdPassingExt;

use crate::fd::{claim_fd_inplace, IntoStdioErr};

/// A wrapper around a socket that combines reading from the socket with tracking
/// received file descriptors. Limits the maximum number of file descriptors that
/// can be received in a single read operation via the `MAX_FDS` parameter.
///
/// # Example
///
/// ```rust
/// use std::collections::VecDeque;
/// use std::io::Cursor;
/// use std::io::Read;
/// use std::os::fd::AsRawFd;
/// use std::os::fd::OwnedFd;
///
/// use mio::net::UnixStream;
/// use rosenpass_util::mio::ReadWithFileDescriptors;
/// use rosenpass_util::io::TryIoResultKindHintExt;
///
/// const MAX_REQUEST_FDS : usize = 2; // Limit to 2 descriptors per read operation
/// let mut read_fd_buffer = VecDeque::<OwnedFd>::new(); // File descriptor queue
///
/// // In this case, the unused writable end of the connection can be ignored
/// let (io_stream, _) = UnixStream::pair().expect("failed to create socket pair");
///
/// // Wait until the output stream is writable...
///
/// // Wrap the socket to start tracking received file descriptors
/// let mut fd_passing_sock = ReadWithFileDescriptors::<MAX_REQUEST_FDS, UnixStream, _, _>::new(
///	&io_stream,
///	&mut read_fd_buffer,
/// );
////
/// // Simulated reads; the actual operations will depend on the protocol (implementation details)
/// let mut recv_buffer = Vec::<u8>::new();
/// let bytes_read = fd_passing_sock.read(&mut recv_buffer[..]).expect("error reading from socket");
/// assert_eq!(bytes_read, 0);
/// assert_eq!(&recv_buffer[..bytes_read], []);
///
/// // Alternatively, it's possible to use the try_io_err_kind_hint utility provided by this crate
/// match fd_passing_sock.read(&mut recv_buffer).try_io_err_kind_hint() {
///     Err(_) => {
///         // Handle errors here ...
///     }
///     Ok(result) => {
///         // Process messages here ...
///         assert_eq!(0, result); // Nothing to read in this example
///     }
/// };
///
/// // The wrapped components can still be accessed
/// assert_eq!(fd_passing_sock.socket().as_raw_fd(), io_stream.as_raw_fd());
/// let (socket, fd_queue) = fd_passing_sock.into_parts();
/// assert_eq!(socket.as_raw_fd(), io_stream.as_raw_fd());
///
/// // Shutdown, cleanup, etc. goes here ...
/// ```
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
    /// Creates a new `ReadWithFileDescriptors` by wrapping a socket and a file
    /// descriptor queue.
    pub fn new(socket: BorrowSock, fds: BorrowFds) -> Self {
        let _sock_dummy = PhantomData;
        Self {
            socket,
            fds,
            _sock_dummy,
        }
    }

    /// Consumes the wrapper and returns the underlying socket and file
    /// descriptor queue.
    pub fn into_parts(self) -> (BorrowSock, BorrowFds) {
        let Self { socket, fds, .. } = self;
        (socket, fds)
    }

    /// Returns a reference to the underlying socket.
    pub fn socket(&self) -> &Sock {
        self.socket.borrow()
    }

    /// Returns a reference to the file descriptor queue.
    pub fn fds(&self) -> &VecDeque<OwnedFd> {
        self.fds.borrow()
    }

    /// Returns a mutable reference to the file descriptor queue.
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
    /// Returns a mutable reference to the underlying socket.
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
