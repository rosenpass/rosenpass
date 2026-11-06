use std::{
    borrow::{Borrow, BorrowMut},
    collections::VecDeque,
    io,
    os::fd::{AsRawFd, BorrowedFd, OwnedFd},
    sync::atomic::{Ordering, fence},
};

use mio::{Interest, Token, event::Source, unix::SourceFd};
use rustix::net::{RecvFlags, SendFlags};
use strum::IntoDiscriminant;
use zerocopy::IntoBytes;

use crate::internal::util::{
    functional::{ApplyExt, SideffectExt},
    int::{modular::Modulus, u64uint::U64USize},
    io::{
        fd_stream::{recv_fd_msg, send_fd_msg},
        handle_interrupted,
    },
    mem::{CopyExt, DiscardResultExt},
    option::SomeExt,
    ringbuf::sched::RingBufferScheduler,
    rustix::{IntoStdioErr, SENDFLAGS_NOSIGNAL},
};

use super::{
    ShmProtocolViolation, ShmStreamError,
    shared::{ChunkHeader, ChunkLenPrefix, SharedState},
};

/// Key state machine for the sender.
///
/// The transactions are concerned with rolling back a write when sending the
/// chunk announcement fails (e.g. WOULDBLOCK); terminated means the entire sender
/// is finished and no more data can be sent
#[derive(
    Debug,
    derive_more::IsVariant,
    derive_more::TryUnwrap,
    strum::EnumDiscriminants,
    derive_more::From,
)]
#[try_unwrap(owned, ref, ref_mut)]
enum SenderStateMachine {
    AwaitingChunk(AwaitingChunk),
    CurrentChunk(CurrentChunk),
    Terminated(Terminated),
}

#[derive(Debug)]
struct AwaitingChunk {
    scheduler: RingBufferScheduler,
}

#[derive(Debug)]
struct CurrentChunk {
    scheduler: RingBufferScheduler,
    pre_transaction_write_counter: u64,
}

#[derive(Debug, derive_more::Constructor)]
struct Terminated {
    scheduler: RingBufferScheduler,
    reason: ShmStreamError,
}

impl SenderStateMachine {
    fn scheduler(&self) -> &RingBufferScheduler {
        match self {
            Self::AwaitingChunk(state) => &state.scheduler,
            Self::CurrentChunk(state) => &state.scheduler,
            Self::Terminated(state) => &state.scheduler,
        }
    }

    fn scheduler_mut(&mut self) -> &mut RingBufferScheduler {
        match self {
            Self::AwaitingChunk(state) => &mut state.scheduler,
            Self::CurrentChunk(state) => &mut state.scheduler,
            Self::Terminated(state) => &mut state.scheduler,
        }
    }

    /// Start a chunk transaction, remembering the write counter for rollback.
    fn begin_chunk(&mut self) {
        assert!(matches!(self, Self::AwaitingChunk(_)));
        let scheduler = *self.scheduler();
        *self = Self::CurrentChunk(CurrentChunk {
            pre_transaction_write_counter: scheduler.items_written(),
            scheduler,
        });
    }

    /// Discard staged writes. The read counter is kept, so acknowledgements
    /// received since [Self::begin_chunk] are not undone.
    fn discard_chunk(&mut self) {
        let Self::CurrentChunk(state) = self else {
            panic!("rollback requires an active sender transaction");
        };
        let scheduler = RingBufferScheduler::from_counters(
            state.scheduler.buf_len(),
            state.pre_transaction_write_counter,
            state.scheduler.items_read(),
        );
        *self = Self::AwaitingChunk(AwaitingChunk { scheduler });
    }

    /// Finish the chunk transaction, keeping the staged writes.
    fn commit_chunk(&mut self) {
        let Self::CurrentChunk(state) = self else {
            panic!("commit requires an active sender transaction");
        };
        *self = Self::AwaitingChunk(AwaitingChunk {
            scheduler: state.scheduler,
        });
    }

    /// Length of the staged chunk (prefix plus payload), if a transaction is active.
    fn current_chunk_len(&self) -> Option<u64> {
        let Self::CurrentChunk(state) = self else {
            return None;
        };

        let old = state.pre_transaction_write_counter;
        let new = state.scheduler.items_written();
        let modulus = Modulus::new_or_panic(state.scheduler.buf_len())
            .double()
            .unwrap();

        let r = modulus.formula([old, new], |params| {
            let [old, new] = params;
            new - old
        });

        Some(r)
    }

    fn data_avail_without_current_chunk(&self) -> u64 {
        self.scheduler().data_avail() - self.current_chunk_len().unwrap_or(0)
    }
}

#[derive(Debug)]
pub struct SenderState {
    // The peer may hold a duplicate of this socket and clear O_NONBLOCK on the shared open
    // file description; sender and receiver therefore pass MSG_DONTWAIT on every call.
    notification_socket: OwnedFd,
    state: SenderStateMachine,
    unacknowledged_chunk_lengths: VecDeque<usize>,
    notification_socket_shutdown_issued: Option<()>,
}

impl SenderState {
    // Constructor
    pub fn new(notification_socket: OwnedFd, scheduler: RingBufferScheduler) -> Self {
        Self {
            notification_socket,
            state: SenderStateMachine::AwaitingChunk(AwaitingChunk { scheduler }),
            unacknowledged_chunk_lengths: VecDeque::new(),
            notification_socket_shutdown_issued: None,
        }
    }
}

pub struct SenderFrame<Shared, Sender> {
    pub shared: Shared,
    pub sender: Sender,
}

impl<Shared: Borrow<SharedState>, Sender: Borrow<SenderState>> SenderFrame<Shared, Sender> {
    fn shared(&self) -> &SharedState {
        self.shared.borrow()
    }

    fn sender(&self) -> &SenderState {
        self.sender.borrow()
    }

    fn notification_socket(&self) -> &OwnedFd {
        self.sender().notification_socket.borrow()
    }

    fn state(&self) -> &SenderStateMachine {
        self.sender().state.borrow()
    }

    fn notification_socket_shutdown_issued(&mut self) -> Option<()> {
        self.sender().notification_socket_shutdown_issued
    }

    /// The failure that terminated the sender, if any.
    fn termination_reason(&self) -> Option<ShmStreamError> {
        let sender = self.sender.borrow();
        match &sender.state {
            SenderStateMachine::Terminated(Terminated { reason, .. }) => Some(*reason),
            _ => None,
        }
    }

    fn scheduler(&self) -> &RingBufferScheduler {
        self.state().scheduler()
    }

    /// Total length of the ring buffer
    fn buf_len(&self) -> usize {
        self.scheduler()
            .buf_len()
            .apply(U64USize::new_or_panic)
            .usize()
    }

    /// How much unused space there is in the buffer
    fn chunk_space_avail(&self) -> usize {
        self.scheduler()
            .space_avail()
            .apply(U64USize::new_or_panic)
            .usize()
    }

    /// Committed chunk len of the current chunk
    fn current_chunk_len(&self) -> Option<usize> {
        self.state()
            .current_chunk_len()?
            .apply(U64USize::new_or_panic)
            .usize()
            .some()
    }

    /// Committed payload len of the current chunk
    fn current_payload_len(&self) -> Option<usize> {
        self.current_chunk_len()?
            .saturating_sub(size_of::<ChunkHeader>())
            .some()
    }

    /// How much of the ring buffer is currently occupied
    fn chunk_data_inflight(&self) -> usize {
        self.state()
            .data_avail_without_current_chunk()
            .apply(U64USize::new_or_panic)
            .usize()
    }

    /// How much chunk data we could sent (disregarding the current chunk)
    fn chunk_space_avail_without_current_chunk(&self) -> usize {
        self.buf_len()
            .checked_sub(self.chunk_data_inflight())
            .unwrap()
    }

    /// How much payload data we could sent (disregarding the current chunk)
    fn payload_space_avail_without_current_chunk(&self) -> usize {
        self.chunk_space_avail_without_current_chunk()
            .saturating_sub(size_of::<ChunkHeader>())
    }

    /// There is too little space for the current (or the next) chunk to ever transmit any data
    fn chunk_is_doomed(&self) -> bool {
        self.payload_space_avail_without_current_chunk() == 0
    }

    fn current_chunk(&self) -> Option<&CurrentChunk> {
        self.state().try_unwrap_current_chunk_ref().ok()
    }

    fn terminated(&self) -> Option<&Terminated> {
        self.state().try_unwrap_terminated_ref().ok()
    }

    fn is_current_chunk(&self) -> bool {
        self.current_chunk().is_some()
    }
}

impl<Shared: Borrow<SharedState>, Sender: BorrowMut<SenderState>> SenderFrame<Shared, Sender> {
    pub fn write_with_fds(
        &mut self,
        source: &[u8],
        fds: &[BorrowedFd<'_>],
    ) -> Result<usize, ShmStreamError> {
        if let Some(reason) = self.termination_reason() {
            Err(reason)?;
        } else if source.is_empty() {
            return Ok(0);
        }

        let payload_len = std::cmp::min(
            self.payload_space_avail_without_current_chunk(),
            source.len(),
        );
        let header = ChunkHeader::new_from_usize(payload_len);

        self.begin_chunk();
        self.write_chunk_bytes(header.as_bytes());
        self.write_chunk_bytes(&source[..payload_len]);
        assert_eq!(self.current_payload_len().unwrap(), payload_len);

        if !self.chunk_is_doomed() {
            // Technically fences are not really meant for our system IO based
            // synchronization, but we still include a fence for good measure!
            fence(Ordering::Release);
        }

        // Send chunk announcement
        let res = self
            .send_chunk_announcement(fds)
            .map(|_| payload_len)
            .map_err(|e| e.into())
            .map_err(|e| ShmStreamError::normalize(&e)); // EAGAIN -> EWOULDBLOCK

        // Handle errors sending chunk announcement
        use ShmStreamError as F;
        res.sideeffect(|res| {
            use rustix::io::Errno as E;
            match res {
                Ok(_) => self.commit_chunk(),
                Err(F::Io(E::WOULDBLOCK)) => self.discard_chunk(),
                Err(e) => self.terminate(*e).discard_result(),
            };
        })
    }

    fn write_chunk_bytes(&mut self, source: &[u8]) {
        assert!(self.is_current_chunk());

        if self.chunk_is_doomed() {
            return;
        }

        let len = std::cmp::min(self.chunk_space_avail(), source.len());
        let source = &source[..len];
        let mut sched = self.scheduler().copy();

        self.shared().write_to_sender_buffer(&mut sched, source);

        *self.scheduler_mut() = sched;
    }

    fn send_chunk_announcement(&mut self, fds: &[BorrowedFd<'_>]) -> Result<(), rustix::io::Errno> {
        use rustix::io::Errno as E;

        let fd = self.notification_socket();
        handle_interrupted(|| {
            // If chunk is doomed (no transmission possible), still touch the notification_socket
            // so we can detect any IO errors
            if self.chunk_is_doomed() {
                rustix::net::send(fd, &[], SENDFLAGS_NOSIGNAL | SendFlags::DONTWAIT)?;
                Err(E::WOULDBLOCK)?;
            }

            // If the chunk is not doomed, actually transmit the notification
            match send_fd_msg(self.notification_socket(), b"\0", fds, SendFlags::DONTWAIT) {
                // All right; announcement sent
                Ok(1) => Ok(()),
                // Invalid result
                Ok(_) => Err(E::IO),
                // Other error
                Err(e) => Err(e),
            }
        })
    }

    pub fn service_chunk_acknowledgements(&mut self) -> Result<(), ShmStreamError> {
        use ShmStreamError as N;
        use rustix::io::Errno as E;

        if let Some(term) = self.terminated() {
            return Err(term.reason);
        }

        // Collect all the acknowledgements and calculate how many bytes were read
        loop {
            match self.recv_chunk_acknowledgement().map_err(|e| e.normalize()) {
                Err(N::Io(E::WOULDBLOCK)) => return Ok(()),
                Err(e) => {
                    self.terminate(e).discard_result();
                    Err(e)?;
                }
                Ok(ack_len) => {
                    // Register reads with the scheduler
                    let ack_len = U64USize::new_or_panic(ack_len).u64();
                    *self.scheduler_mut() = self.scheduler().register_read(ack_len);
                }
            };
        }
    }

    fn recv_chunk_acknowledgement(&mut self) -> Result<usize, ShmStreamError> {
        use ShmProtocolViolation as V;

        let mut ack_byte = 0u8;

        // Do the io/recv
        let res = handle_interrupted(|| {
            let fd = self.notification_socket();
            let dst = std::slice::from_mut(&mut ack_byte);
            recv_fd_msg(fd, dst, 0, RecvFlags::DONTWAIT)
                .apply(ShmStreamError::cache_shutdown_as_epipe)
        })?;

        // Dispatch errors in the ReadWithFdsResult
        if res.fds_truncated || !res.fds.is_empty() {
            Err(V::FdsOnAck)?;
        }

        // Dispatch data errors
        if ack_byte != 0 {
            Err(V::InvalidChunkAcknowledgement)?;
        }

        // Recover the ack len
        let Some(ack_len) = self.unacknowledged_chunk_lengths_mut().pop_front() else {
            return Err(V::UnexpectedChunkAcknowledgement)?;
        };

        Ok(ack_len)
    }

    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.terminate(ShmStreamError::SHUTDOWN)
            .map_err(|e| e.into_stdio_err())
    }

    fn terminate(&mut self, reason: ShmStreamError) -> Result<(), rustix::io::Errno> {
        // Shutdown the underlying stream
        let res = self.issue_notification_socket_shutdown();

        use SenderStateMachineDiscriminants as S;
        match self.state().discriminant() {
            S::AwaitingChunk => {}
            S::CurrentChunk => self.discard_chunk(),
            S::Terminated => return Ok(()),
        }

        // Transition to the new state
        *self.state_mut() = self
            .scheduler()
            .copy()
            .apply(|sched| Terminated::new(sched, reason))
            .into();

        res
    }

    fn issue_notification_socket_shutdown(&mut self) -> Result<(), rustix::io::Errno> {
        use rustix::net::{Shutdown, shutdown};

        if self.notification_socket_shutdown_issued().is_some() {
            return Ok(());
        }

        shutdown(self.notification_socket(), Shutdown::Both)?;

        *self.notification_socket_shutdown_issued_mut() = Some(());

        Ok(())
    }

    fn begin_chunk(&mut self) {
        self.state_mut().begin_chunk();
    }

    fn discard_chunk(&mut self) {
        self.state_mut().discard_chunk();
    }

    fn commit_chunk(&mut self) {
        let chunk_len = self.current_payload_len().unwrap();
        self.unacknowledged_chunk_lengths_mut()
            .push_back(chunk_len + size_of::<ChunkLenPrefix>());
        self.state_mut().commit_chunk();
    }

    fn sender_mut(&mut self) -> &mut SenderState {
        self.sender.borrow_mut()
    }

    fn state_mut(&mut self) -> &mut SenderStateMachine {
        self.sender_mut().state.borrow_mut()
    }

    fn unacknowledged_chunk_lengths_mut(&mut self) -> &mut VecDeque<usize> {
        self.sender_mut().unacknowledged_chunk_lengths.borrow_mut()
    }

    fn scheduler_mut(&mut self) -> &mut RingBufferScheduler {
        self.state_mut().scheduler_mut()
    }

    fn notification_socket_shutdown_issued_mut(&mut self) -> &mut Option<()> {
        self.sender_mut()
            .notification_socket_shutdown_issued
            .borrow_mut()
    }
}

impl<Shared: Borrow<SharedState>, Receiver: Borrow<SenderState>> SenderFrame<Shared, Receiver> {
    /// Register this role's socket natively; readiness is only a retry hint and
    /// the outer stream coordinates both roles and any best-effort cleanup.
    pub fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.notification_socket().as_raw_fd()).register(registry, token, interests)
    }

    /// Update this socket in the supplied registry, returning its native result.
    pub fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.notification_socket().as_raw_fd()).reregister(registry, token, interests)
    }

    /// Remove this socket from the supplied registry without changing payload state.
    pub fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        SourceFd(&self.notification_socket().as_raw_fd()).deregister(registry)
    }
}
