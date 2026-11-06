//! Byte streams with file-descriptor queues and adapters for the length-prefix codecs.
//!
//! [recv_fd_msg] and [send_fd_msg] provide convenient low-level wrappers for performing
//! file descriptor passing directly on unix sockets.

use std::{
    collections::VecDeque,
    io,
    mem::MaybeUninit,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use arrayvec::ArrayVec;
use rustix::{
    io::{FdFlags, fcntl_setfd},
    net::{
        RecvAncillaryBuffer, RecvAncillaryMessage, RecvFlags, ReturnFlags, SendAncillaryBuffer,
        SendAncillaryMessage, SendFlags,
    },
};

use crate::internal::util::mem::DiscardResultExt;
use crate::internal::util::rustix::SENDFLAGS_NOSIGNAL;

/// Maximum descriptors carried by a file-descriptor passing stream.
pub const MAX_SENDMSG_FDS: usize = 253;

/// Result of [recv_fd_msg()] and [FdPassingStream::read_with_fds()]
#[derive(Debug, Default)]
pub struct ReadWithFdsResult {
    /// The number of data bytes that where read into the given buffer
    pub data_read: usize,
    /// Whether there where extra file descriptors sent by the other party
    /// that had to be dropped.
    pub fds_truncated: bool,
    /// The file descriptors we received. Note that this being empty,
    /// does not imply no file descriptors where sent by the other party.
    ///
    /// Some implementations (e.g. unix sockets on Linux) may choose to
    /// truncate the list of file descriptors if the number exceeds what
    /// the recipient can accommodate; other implementations (e.g. unix
    /// sockets on FreeBSD) may discard all file descriptors in this case.
    /// Always check [Self::fds_truncated] to detect any file descriptor truncation.
    pub fds: ArrayVec<OwnedFd, MAX_SENDMSG_FDS>,
}

impl ReadWithFdsResult {
    /// Construct a [Self] from its fields
    pub fn new(
        data_read: usize,
        fds_truncated: bool,
        fds: ArrayVec<OwnedFd, MAX_SENDMSG_FDS>,
    ) -> Self {
        Self {
            data_read,
            fds_truncated,
            fds,
        }
    }

    /// A result with no bytes read and no file descriptors received
    pub fn empty() -> Self {
        Self::new(0, false, ArrayVec::new())
    }
}

/// Receive bytes and file descriptors on a unix socket through recvmsg(2).
///
/// If bytes_dst is empty, this is always a no-op. `flags` are added to the
/// flags this function always uses.
///
/// EINTR must be handled by the caller.
pub fn recv_fd_msg<Fd: AsFd>(
    fd: Fd,
    bytes_dst: &mut [u8],
    max_fds: usize,
    flags: RecvFlags,
) -> Result<ReadWithFdsResult, rustix::io::Errno> {
    /// Ask the kernel to mark received rights close-on-exec atomically.
    ///
    /// Not every Unix platform exposes `MSG_CMSG_CLOEXEC` (notably Apple). There,
    /// [recv_fd_msg] receives without the flag and sets `FD_CLOEXEC` explicitly.
    const RECV_RIGHTS_FLAGS: RecvFlags = cfg_select! {
        target_vendor = "apple" => RecvFlags::empty(),
        _  => RecvFlags::CMSG_CLOEXEC,
    };

    /// Maximum size of the ancillary data buffer, sizes for the maximum number of fds
    /// (my kingdom for alloca(3))
    const MAX_ANCILLARY_SIZE: usize = rustix::cmsg_space!(ScmRights(MAX_SENDMSG_FDS));

    if bytes_dst.is_empty() {
        return Ok(ReadWithFdsResult::empty());
    }

    // The number of file descriptors we can return to the caller.
    let max_fds = max_fds.min(MAX_SENDMSG_FDS);

    // Size of the ancillary buffer to use; ancillary_size <= MAX_ANCILLARY_SIZE.
    // Without any buffer, the kernel truncates (and closes) all ancillary data,
    // including descriptors other than SCM_RIGHTS such as SCM_PIDFD.
    let ancillary_size = match max_fds {
        0 => 0,
        _ => rustix::cmsg_space!(ScmRights(max_fds)),
    };

    // Ancillary data buffer
    let mut ancillary = [MaybeUninit::uninit(); MAX_ANCILLARY_SIZE];
    let mut ancillary = RecvAncillaryBuffer::new(&mut ancillary[..ancillary_size]);

    // IO vector (recvmsg(2) expects scatter/gather IO)
    let mut iov = [io::IoSliceMut::new(bytes_dst)];

    // Actually perform IO
    let res = rustix::net::recvmsg(fd, &mut iov, &mut ancillary, RECV_RIGHTS_FLAGS | flags)?;

    // Collect all the ScmRights (these are the ones that contain FDs) messages into one big
    // file descriptor iterator. The ancillary buffer is sized for at most
    // MAX_SENDMSG_FDS rights, so this cannot overflow the fixed buffer.
    let mut fds: ArrayVec<OwnedFd, MAX_SENDMSG_FDS> = ancillary
        .drain()
        .filter_map(|ancil_msg| match ancil_msg {
            RecvAncillaryMessage::ScmRights(fds) => Some(fds),
            // e.g. SCM_CREDENTIALS: carries no descriptors
            _ => None,
        })
        .flatten()
        .collect();

    // Whether any file descriptors where dropped
    let fds_truncated = res.flags.contains(ReturnFlags::CTRUNC) || fds.len() > max_fds;

    // Drop any superfluous file descriptors
    while fds.len() > max_fds {
        fds.pop().discard_result();
    }

    // Only the fallback needs explicit CLOEXEC. With the atomic receive flag,
    // a redundant fcntl could fail after consuming bytes and rights, losing
    // their attachment position even though CLOEXEC was already set.
    if RECV_RIGHTS_FLAGS.is_empty() {
        for fd in &fds {
            fcntl_setfd(fd, FdFlags::CLOEXEC)?;
        }
    }

    Ok(ReadWithFdsResult::new(res.bytes, fds_truncated, fds))
}

/// Send bytes and file descriptors on a unix socket through sendmsg(2)
///
/// If bytes is empty, this is always a no-op. `flags` are added to the
/// flags this function always uses.
///
/// EINTR must be handled by the caller.
///
/// When the underlying sendmsg(2) call reports no progress (zero bytes written),
/// this is reported as EIO, so callers can safely assume that their file descriptors
/// where written
///
/// # Panics
///
/// `fds` must hold at most [MAX_SENDMSG_FDS] descriptors; chunking larger
/// queues is the caller's responsibility.
pub fn send_fd_msg<Fd: AsFd>(
    fd: Fd,
    bytes: &[u8],
    fds: &[BorrowedFd<'_>],
    flags: SendFlags,
) -> Result<usize, rustix::io::Errno> {
    /// Maximum size of the ancillary data buffer, sizes for the maximum number of fds
    /// (my kingdom for alloca(3))
    const MAX_ANCILLARY_SIZE: usize = rustix::cmsg_space!(ScmRights(MAX_SENDMSG_FDS));

    assert!(fds.len() <= MAX_SENDMSG_FDS);

    if bytes.is_empty() {
        return Ok(0);
    }

    // Allocate the buffer for ancillary messages
    let mut ancillary = [MaybeUninit::uninit(); MAX_ANCILLARY_SIZE];
    let mut ancillary = SendAncillaryBuffer::new(&mut ancillary);

    // Add the file descriptors to the ancillary data; the if statement is deliberate. Without
    // it, we might send a message with zero-sized ancillary data, which is rejected on some
    // systems.
    if !fds.is_empty() {
        assert!(ancillary.push(SendAncillaryMessage::ScmRights(fds)));
    }

    // sendmsg(2) expects scatter/gather IO
    let iov = [io::IoSlice::new(bytes)];

    // Do the sendmsg(2) call
    let bytes_written = rustix::net::sendmsg(fd, &iov, &mut ancillary, SENDFLAGS_NOSIGNAL | flags)?;

    // No errno describes a zero-progress send; EIO is the closest
    // portable error for a transport that cannot make progress.
    // This should not happen
    if bytes_written == 0 {
        log::error!(
            "Zero progress send in send_fd_msg. This should not happen and might indicate an operating system bug."
        );
        return Err(rustix::io::Errno::IO);
    }

    Ok(bytes_written)
}

/// A byte stream that receives and sends owned file descriptors alongside bytes.
pub trait FdPassingStream {
    /// Failure type of [Self::read_with_fds].
    type ReadError;

    /// Failure type of [Self::write_with_fds].
    type WriteError;

    /// Per-call options for [Self::read_with_fds_config].
    type ReadConfig: Default;

    /// Per-call options for [Self::write_with_fds_config].
    type WriteConfig: Default;

    /// Read bytes and all newly received descriptors.
    ///
    /// New descriptors attach to the first returned byte; reads do not cross a
    /// later descriptor attachment position. Reception is bounded by
    /// `max_new_fds`. Callers must inspect [ReadWithFdsResult::fds_truncated]
    /// before relying on the returned descriptors. On error no descriptors are
    /// returned and implementations must close any rights they received.
    /// Empty destinations do no IO; zero bytes for a nonempty destination means EOF.
    fn read_with_fds(
        &mut self,
        dst: &mut [u8],
        max_new_fds: usize,
    ) -> Result<ReadWithFdsResult, Self::ReadError> {
        self.read_with_fds_config(dst, max_new_fds, Default::default())
    }

    /// [Self::read_with_fds] with explicit per-call options.
    fn read_with_fds_config(
        &mut self,
        dst: &mut [u8],
        max_new_fds: usize,
        config: Self::ReadConfig,
    ) -> Result<ReadWithFdsResult, Self::ReadError>;

    /// Send bytes with all given descriptors attached to the first byte.
    /// Empty sources do no IO and send no descriptors. Implementations attach
    /// every supplied descriptor or fail, so after positive progress the caller
    /// may remove all of them. Success implies positive progress: a zero-byte
    /// result for a nonempty source is an error. Supplying more than
    /// [MAX_SENDMSG_FDS] descriptors is a caller error.
    fn write_with_fds(
        &mut self,
        src: &[u8],
        fds: &[BorrowedFd<'_>],
    ) -> Result<usize, Self::WriteError> {
        self.write_with_fds_config(src, fds, Default::default())
    }

    /// [Self::write_with_fds] with explicit per-call options.
    fn write_with_fds_config(
        &mut self,
        src: &[u8],
        fds: &[BorrowedFd<'_>],
        config: Self::WriteConfig,
    ) -> Result<usize, Self::WriteError>;
}

/// [FdPassingStream::ReadConfig] for unix sockets: extra [recv_fd_msg] flags.
#[derive(Debug, Clone, Copy)]
pub struct UnixReadConfig(pub RecvFlags);

impl Default for UnixReadConfig {
    fn default() -> Self {
        Self(RecvFlags::empty())
    }
}

/// [FdPassingStream::WriteConfig] for unix sockets: extra [send_fd_msg] flags.
#[derive(Debug, Clone, Copy)]
pub struct UnixWriteConfig(pub SendFlags);

impl Default for UnixWriteConfig {
    fn default() -> Self {
        Self(SendFlags::empty())
    }
}

impl FdPassingStream for std::os::unix::net::UnixStream {
    type ReadError = rustix::io::Errno;
    type WriteError = rustix::io::Errno;
    type ReadConfig = UnixReadConfig;
    type WriteConfig = UnixWriteConfig;

    fn read_with_fds_config(
        &mut self,
        dst: &mut [u8],
        max_new_fds: usize,
        config: Self::ReadConfig,
    ) -> Result<ReadWithFdsResult, Self::ReadError> {
        recv_fd_msg(self.as_fd(), dst, max_new_fds, config.0)
    }

    fn write_with_fds_config(
        &mut self,
        src: &[u8],
        fds: &[BorrowedFd<'_>],
        config: Self::WriteConfig,
    ) -> Result<usize, Self::WriteError> {
        send_fd_msg(self.as_fd(), src, fds, config.0)
    }
}

impl FdPassingStream for mio::net::UnixStream {
    type ReadError = rustix::io::Errno;
    type WriteError = rustix::io::Errno;
    type ReadConfig = UnixReadConfig;
    type WriteConfig = UnixWriteConfig;

    fn read_with_fds_config(
        &mut self,
        dst: &mut [u8],
        max_new_fds: usize,
        config: Self::ReadConfig,
    ) -> Result<ReadWithFdsResult, Self::ReadError> {
        recv_fd_msg(self.as_fd(), dst, max_new_fds, config.0)
    }

    fn write_with_fds_config(
        &mut self,
        src: &[u8],
        fds: &[BorrowedFd<'_>],
        config: Self::WriteConfig,
    ) -> Result<usize, Self::WriteError> {
        send_fd_msg(self.as_fd(), src, fds, config.0)
    }
}

/// An [`io::Read`] adapter that also reads file descriptors via [FdPassingStream].
///
/// Calls to [std::io::Read::read] attach any file descriptors to the
/// given file descriptor buffers behind the scenes.
pub struct FdStreamReader<'a, S: ?Sized> {
    stream: &'a mut S,
    fds: &'a mut VecDeque<OwnedFd>,
    max_fds_per_message: usize,
}

impl<'a, S: ?Sized> FdStreamReader<'a, S> {
    /// Constructor
    pub fn new(
        stream: &'a mut S,
        fds: &'a mut VecDeque<OwnedFd>,
        max_fds_per_message: usize,
    ) -> Self {
        Self {
            stream,
            fds,
            max_fds_per_message,
        }
    }
}

impl<S: FdPassingStream + ?Sized> io::Read for FdStreamReader<'_, S>
where
    S::ReadError: Into<io::Error>,
{
    fn read(&mut self, dst: &mut [u8]) -> io::Result<usize> {
        let max_new_fds = self.max_fds_per_message.saturating_sub(self.fds.len());
        let result = self
            .stream
            .read_with_fds(dst, max_new_fds)
            .map_err(Into::into)?;
        if result.fds_truncated {
            return Err(io::Error::other("Received ancillary data was truncated"));
        }
        self.fds.extend(result.fds);
        Ok(result.data_read)
    }
}

/// An [`io::Write`] adapter that also writes file descriptors via [FdPassingStream].
///
/// The given file descriptors are sent with the first successful
/// [std::io::Write::write()].
pub struct FdStreamWriter<'a, S: ?Sized> {
    stream: &'a mut S,
    fds: &'a [BorrowedFd<'a>],
}

impl<'a, S: ?Sized> FdStreamWriter<'a, S> {
    /// Constructor
    pub fn new(stream: &'a mut S, fds: &'a [BorrowedFd<'a>]) -> Self {
        Self { stream, fds }
    }
}

impl<S: FdPassingStream + ?Sized> io::Write for FdStreamWriter<'_, S>
where
    S::WriteError: Into<io::Error>,
{
    fn write(&mut self, src: &[u8]) -> io::Result<usize> {
        if src.is_empty() {
            return Ok(0);
        }

        // All queued descriptors go out with the first byte, and one sendmsg()
        // carries at most MAX_SENDMSG_FDS rights.
        if self.fds.len() > MAX_SENDMSG_FDS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "too many file descriptors for one fd-passing write",
            ));
        }

        let written = self
            .stream
            .write_with_fds(src, self.fds)
            .map_err(Into::into)?;

        // Success means the first byte and every offered descriptor went out.
        if written == 0 {
            return Err(io::ErrorKind::WriteZero.into());
        }

        self.fds = &[];

        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
