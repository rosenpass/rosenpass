//! Owned shared-memory byte stream with mio readiness.

use std::{
    io,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
};

use mio::{Interest, Token, event::Source};

use crate::internal::util::{
    functional::ApplyExt,
    io::{
        IoErrorKind, TryIoErrorKind,
        fd_stream::{FdPassingStream, ReadWithFdsResult},
    },
    ipc::shm::stream::mio::shared::SHUTDOWN_ERRNO,
    mem::{CopyExt, DiscardResultExt},
    ringbuf::sched::RingBufferScheduler,
    rustix::{FileStatusFlagsExt, GetSocketConnectedness, GetUnixSocketType, IntoStdioErr},
};

use super::super::SharedMemorySegment;

mod receiver;
mod sender;
mod shared;

use receiver::{ReceiverFrame, ReceiverState};
use sender::{SenderFrame, SenderState};
use shared::{ChunkHeader, SharedState};

pub use shared::validate_buffer_geometry;

/// Width of the on-ring chunk length prefix.
const CHUNK_PREFIX_LEN: usize = std::mem::size_of::<ChunkHeader>();
/// Smallest legal payload in a chunk: empty chunks are invalid.
const MIN_PAYLOAD_LEN: usize = 1;
/// Smallest legal ring chunk: prefix plus minimum payload.
const MIN_CHUNK_LEN: usize = CHUNK_PREFIX_LEN + MIN_PAYLOAD_LEN;
/// Smallest supported per-direction ring capacity.
pub(super) const MIN_RING_LEN: usize = MIN_CHUNK_LEN;
/// Smallest supported whole buffer: two equal rings.
pub(super) const MIN_SHM_BUF_LEN: usize = MIN_RING_LEN * 2;
/// Maximum per-direction ring capacity (1 MiB).
pub(super) const MAX_RING_LEN: usize = 1024 * 1024;
/// Maximum whole buffer: two maximum rings (2 MiB total).
pub(super) const MAX_SHM_BUF_LEN: usize = 2 * MAX_RING_LEN;

/// Which half of the mapping carries the outgoing vs. the incoming payload ring.
#[derive(Debug, Clone, Copy)]
pub enum RingLayout {
    /// Outgoing ring is the low half; incoming ring is the high half.
    LowSendHighReceive,
    /// Outgoing ring is the high half; incoming ring is the low half.
    LowReceiveHighSend,
}

/// Failure to construct or validate shared-memory stream resources.
///
/// This covers an invalid mapping/ring configuration and owned-endpoint
/// inspection. Upgrade finishing also uses [Self::Io] for local failures
/// after validation and preparation.
#[derive(Debug, thiserror::Error)]
pub enum ShmStreamCreationError {
    /// Unsupported per-direction capacity.
    #[error("Ring size must be between {MIN_RING_LEN} and {MAX_RING_LEN} bytes")]
    InvalidRingSize,
    /// The mapping must split into two equal rings.
    #[error("Mapping length must equal twice the ring size")]
    InvalidMappingLength,
    /// Notification sockets must be AF_UNIX stream sockets.
    #[error("Notification sockets must be AF_UNIX stream sockets")]
    NotUnixStreamSocket,
    /// Notification sockets must be connected to a peer.
    #[error("Notification sockets must be connected")]
    UnconnectedSocket,
    /// Socket inspection failed.
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Protocol errors reported by the shared-memory transport.
#[derive(Debug, Clone, Copy, thiserror::Error, PartialEq, Eq)]
pub enum ShmProtocolViolation {
    /// Malformed chunk announcement
    #[error("Invalid chunk announcement byte")]
    InvalidChunkAnnouncement,
    /// A snapshotted payload length was below `MIN_PAYLOAD_LEN` (empty
    /// chunk); oversized lengths are reported as [Self::ControlOverflow].
    #[error("Invalid chunk length")]
    InvalidChunkLength,
    /// An acknowledgment was not NUL.
    #[error("Invalid ack byte")]
    InvalidChunkAcknowledgement,
    /// An acknowledgment had no outstanding local chunk.
    #[error("Unexpected ack")]
    UnexpectedChunkAcknowledgement,
    /// Acknowledgments must not carry descriptors.
    #[error("File descriptors on chunk acknowledgement (forbidden)")]
    FdsOnAck,
    /// Overflow; more reads than the ring buffer could reasonably hold
    #[error("Ring buffer overflow")]
    ControlOverflow,
}

/// Errors raised by shared-memory stream operations
#[derive(Debug, thiserror::Error, PartialEq, Eq, Copy, Clone)]
pub enum ShmStreamError {
    /// An underlying system call failed.
    #[error(transparent)]
    Io(#[from] rustix::io::Errno),
    /// The peer violated the shared-memory transport protocol.
    #[error(transparent)]
    ProtocolViolation(#[from] ShmProtocolViolation),
}

impl ShmStreamError {
    const SHUTDOWN: Self = Self::Io(SHUTDOWN_ERRNO);

    /// Gets rid of redundant error invariants
    ///
    /// Turns EAGAIN into WOULDBLOCK
    fn normalize(&self) -> Self {
        use rustix::io::Errno as E;
        match *self {
            Self::Io(E::AGAIN) => Self::Io(E::WOULDBLOCK),
            e => e,
        }
    }

    fn cache_shutdown_as_epipe<E>(
        res: Result<ReadWithFdsResult, E>,
    ) -> Result<ReadWithFdsResult, Self>
    where
        Self: From<E>,
    {
        let res = res?;
        match res.data_read == 0 {
            false => Ok(res),
            true => Err(Self::SHUTDOWN),
        }
    }

    fn as_external_read_with_fds_result(&self) -> Result<ReadWithFdsResult, Self> {
        let me = self.copy();
        match me == Self::SHUTDOWN {
            false => Err(me),
            true => Ok(ReadWithFdsResult::empty()),
        }
    }

    fn advance_failure_towards_error(&self, other: Self) -> ShmStreamError {
        let me = self.copy();
        match me == Self::SHUTDOWN {
            false => me,
            true => other,
        }
    }
}

impl TryIoErrorKind for ShmStreamError {
    fn try_io_error_kind(&self) -> Option<io::ErrorKind> {
        match self {
            Self::Io(error) => Some(error.io_error_kind()),
            Self::ProtocolViolation(_) => None,
        }
    }
}

impl From<ShmStreamError> for io::Error {
    fn from(error: ShmStreamError) -> Self {
        match error {
            ShmStreamError::Io(error) => error.into_stdio_err(),
            ShmStreamError::ProtocolViolation(error) => io::Error::other(error),
        }
    }
}

/// An owned shared-memory byte stream driven by mio events.
#[derive(Debug)]
pub struct MioFdStream {
    shared: SharedState,
    receiver: ReceiverState,
    sender: SenderState,
}

impl MioFdStream {
    /// Build an owned stream from a protected, populated mapping and both
    /// role-assigned notification endpoints.
    pub fn new(
        segment: SharedMemorySegment,
        layout: RingLayout,
        sender_notification_sock_fd: OwnedFd,
        receiver_notification_sock_fd: OwnedFd,
    ) -> Result<Self, ShmStreamCreationError> {
        use ShmStreamCreationError as E;

        for socket in [&sender_notification_sock_fd, &receiver_notification_sock_fd] {
            if !socket.is_unix_stream_socket().map_err(io::Error::from)? {
                return Err(E::NotUnixStreamSocket);
            } else if !socket.is_connected().map_err(io::Error::from)? {
                return Err(E::UnconnectedSocket);
            }
        }

        for socket in [&sender_notification_sock_fd, &receiver_notification_sock_fd] {
            socket.as_fd().set_nonblocking().map_err(io::Error::from)?;
        }

        let shared = SharedState::new(segment, layout)?;
        let scheduler = u64::try_from(shared.ring_capacity())
            .expect("ring length fits u64")
            .apply(RingBufferScheduler::new);
        Ok(Self {
            shared,
            receiver: ReceiverState::new(receiver_notification_sock_fd, scheduler),
            sender: SenderState::new(sender_notification_sock_fd, scheduler),
        })
    }

    /// Regular shutdown of the stream in the given direction
    ///
    /// Shutting down this streams prevents further data from being written,
    /// but data already sent on the stream can still be read by the recipient.
    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn shutdown(&mut self, direction: std::net::Shutdown) -> io::Result<()> {
        use std::net::Shutdown;
        let (sr, sw) = match direction {
            Shutdown::Read => (true, false),
            Shutdown::Write => (false, true),
            Shutdown::Both => (true, true),
        };

        let rw = sw.then(|| self.sender_frame().shutdown());
        let rr = sr.then(|| self.receiver_frame().shutdown());

        rw.unwrap_or(Ok(()))?;
        rr.unwrap_or(Ok(()))?;

        Ok(())
    }

    fn receiver_frame(&mut self) -> ReceiverFrame<&SharedState, &mut ReceiverState> {
        ReceiverFrame {
            shared: &self.shared,
            receiver: &mut self.receiver,
        }
    }

    fn sender_frame(&mut self) -> SenderFrame<&SharedState, &mut SenderState> {
        SenderFrame {
            shared: &self.shared,
            sender: &mut self.sender,
        }
    }

    /// Visit both independent roles; each lifecycle gates its paired ACK service.
    fn service_chunk_acknowledgements_duplex(&mut self) -> Result<(), ShmStreamError> {
        let r1 = self.receiver_frame().service_chunk_acknowledgements();
        let r2 = self.sender_frame().service_chunk_acknowledgements();

        r1?;
        r2?;

        Ok(())
    }
}

impl Source for MioFdStream {
    fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        _interests: Interest,
    ) -> io::Result<()> {
        let fixed = Interest::READABLE.add(Interest::WRITABLE);

        self.sender_frame().register(registry, token, fixed)?;
        self.receiver_frame().register(registry, token, fixed)?;

        Ok(())
    }

    fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        _interests: Interest,
    ) -> io::Result<()> {
        let fixed = Interest::READABLE.add(Interest::WRITABLE);

        self.sender_frame().reregister(registry, token, fixed)?;
        self.receiver_frame().reregister(registry, token, fixed)?;

        Ok(())
    }

    fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        self.sender_frame().deregister(registry)?;
        self.receiver_frame().deregister(registry)?;
        Ok(())
    }
}

impl FdPassingStream for MioFdStream {
    type ReadError = ShmStreamError;
    type WriteError = ShmStreamError;
    type ReadConfig = ();
    type WriteConfig = ();

    fn read_with_fds_config(
        &mut self,
        destination: &mut [u8],
        max_new_fds: usize,
        _config: (),
    ) -> Result<ReadWithFdsResult, Self::ReadError> {
        if destination.is_empty() {
            return Ok(ReadWithFdsResult::empty());
        }
        self.service_chunk_acknowledgements_duplex()
            .discard_result();
        self.receiver_frame()
            .read_with_fds(destination, max_new_fds)
            .map_err(|e| e.normalize())
    }

    fn write_with_fds_config(
        &mut self,
        source: &[u8],
        fds_to_send: &[BorrowedFd<'_>],
        _config: (),
    ) -> Result<usize, Self::WriteError> {
        if source.is_empty() {
            return Ok(0);
        }
        self.service_chunk_acknowledgements_duplex()
            .discard_result();
        self.sender_frame()
            .write_with_fds(source, fds_to_send)
            .map_err(|e| e.normalize())
    }
}
