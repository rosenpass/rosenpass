use strum::IntoDiscriminant;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};

use super::{ShmProtocolViolation, ShmStreamError, shared::ChunkHeader, shared::SharedState};
use crate::internal::util::{
    functional::{ApplyExt, run},
    io::{
        fd_stream::{ReadWithFdsResult, recv_fd_msg, send_fd_msg},
        handle_interrupted,
    },
    mem::{CopyExt, DiscardResultExt},
    ringbuf::sched::RingBufferScheduler,
    rustix::IntoStdioErr,
};
use mio::{Interest, Token, event::Source, unix::SourceFd};
use rustix::net::{RecvFlags, SendFlags};
use std::{
    borrow::{Borrow, BorrowMut},
    io,
    num::NonZero,
    os::fd::{AsRawFd, OwnedFd},
    sync::atomic::{Ordering, fence},
};

#[derive(
    Debug,
    Clone,
    Copy,
    derive_more::IsVariant,
    derive_more::TryUnwrap,
    strum::EnumDiscriminants,
    derive_more::From,
)]
#[try_unwrap(owned, ref, ref_mut)]
enum OperationalState {
    Normal(Normal),
    Draining(Draining),
    Terminated(Terminated),
}

impl OperationalState {
    pub fn failure(&self) -> Option<ShmStreamError> {
        match self.copy() {
            Self::Normal(_) => None,
            Self::Draining(Draining(e)) => Some(e),
            Self::Terminated(Terminated(e)) => Some(e),
        }
    }

    pub fn with_failure(&self, reason: ShmStreamError) -> Self {
        match self {
            Self::Normal(_) => Normal::new().into(),
            Self::Draining(_) => Draining::new(reason).into(),
            Self::Terminated(_) => Terminated::new(reason).into(),
        }
    }

    pub fn with_potential_failure(&self, reason: Option<ShmStreamError>) -> Self {
        match reason {
            None => Normal::new().into(),
            Some(failure) => self.with_failure(failure),
        }
    }

    // Turns WOULDBLOCK and EAGAIN into the Normal state
    pub fn normalize(&self) -> Self {
        use ShmStreamError as S;
        use rustix::io::Errno as E;

        let failure = self
            .failure()
            .map(|e| e.normalize())
            .filter(|x| *x != S::Io(E::WOULDBLOCK));

        self.with_potential_failure(failure)
    }

    /// Everything is strictly getting more catastrophic and terminal here
    ///
    /// Terminated/Draining with EWOULDBLOCK or EAGAIN are treated as Normal operational state
    pub fn advance_state_towards_termination(&self, advanced: Self) -> Self {
        // Normalization first
        let [me, advanced] = [self, &advanced].map(Self::normalize);

        let current_drain_reason = match me {
            // If this state is normal, the other one can only be as advanced or strictly more
            // advanced than the current operational state
            Self::Normal(_) => return advanced,
            // No modifying terminated states
            Self::Terminated(t) => return Self::Terminated(t),
            // This is getting complicated, we actually need to upgrade
            Self::Draining(Draining(e)) => e,
        };

        // Get the failure from the advanced reason
        let Some(new_reason) = advanced.failure() else {
            // If the is no failure, the advanced state must be Normal, in which
            // case the current state is considered more advanced towards termination
            // since we are already at draining
            return Draining::new(current_drain_reason).into();
        };

        // Advance EOF/terminated towards real errors (but not the other way around)
        // the advanced state cannot be Normal here, since that case
        // returned above
        advanced.with_failure(current_drain_reason.advance_failure_towards_error(new_reason))
    }
}

#[derive(Debug, Copy, Clone, derive_more::Constructor)]
struct Normal;

#[derive(Debug, Copy, Clone, derive_more::Constructor)]
struct Draining(ShmStreamError);

#[derive(Debug, Copy, Clone, derive_more::Constructor)]
struct Terminated(ShmStreamError);

#[derive(Debug)]
pub struct ReceiverState {
    notification_socket: OwnedFd,
    scheduler: RingBufferScheduler,
    state: OperationalState,
    pending_ack_count: usize,
    notification_socket_shutdown_issued: Option<()>,
}

impl ReceiverState {
    /// Take ownership of the notification socket, starting with no chunk in progress.
    pub fn new(notification_socket: OwnedFd, scheduler: RingBufferScheduler) -> Self {
        let pending_ack_count = 0;
        let state = Normal::new().into();
        let notification_socket_shutdown_issued = None;
        Self {
            notification_socket,
            scheduler,
            state,
            pending_ack_count,
            notification_socket_shutdown_issued,
        }
    }
}

pub struct ReceiverFrame<Shared, Receiver> {
    pub shared: Shared,
    pub receiver: Receiver,
}

impl<Shared: Borrow<SharedState>, Receiver: Borrow<ReceiverState>> ReceiverFrame<Shared, Receiver> {
    fn shared(&self) -> &SharedState {
        self.shared.borrow()
    }

    fn receiver(&self) -> &ReceiverState {
        self.receiver.borrow()
    }

    fn notification_socket(&self) -> &OwnedFd {
        self.receiver().notification_socket.borrow()
    }

    fn scheduler(&self) -> &RingBufferScheduler {
        self.receiver().scheduler.borrow()
    }

    fn state(&self) -> &OperationalState {
        self.receiver().state.borrow()
    }

    fn notification_socket_shutdown_issued(&self) -> Option<()> {
        self.receiver().notification_socket_shutdown_issued
    }

    fn pending_ack_count(&self) -> usize {
        self.receiver().pending_ack_count
    }

    fn remaining_chunk_bytes(&self) -> usize {
        self.scheduler().data_avail() as usize
    }

    fn has_partially_read_chunk(&self) -> bool {
        self.remaining_chunk_bytes() > 0
    }

    fn cached_failure(&self) -> Option<ShmStreamError> {
        use OperationalState as S;
        match self.state().copy() {
            S::Normal(_) => None,
            S::Draining(Draining(e)) => Some(e),
            S::Terminated(Terminated(e)) => Some(e),
        }
    }

    fn ensure_live_for_read(&self) -> Result<(), ShmStreamError> {
        use OperationalState as S;
        match self.state().copy() {
            S::Normal(_) => Ok(()),
            S::Draining(_) => Ok(()),
            S::Terminated(Terminated(e)) => Err(e),
        }
    }

    fn ensure_live_for_ack_service(&self) -> Result<(), ShmStreamError> {
        match self.cached_failure() {
            Some(failure) => Err(failure),
            None => Ok(()),
        }
    }

    fn chunk_space_avail(&self) -> usize {
        self.scheduler().space_avail() as usize
    }
}

impl<Shared: Borrow<SharedState>, Receiver: BorrowMut<ReceiverState>>
    ReceiverFrame<Shared, Receiver>
{
    /// Read at most one chunk directly into the destination. Descriptors
    /// announced with a chunk are returned with its first payload byte, or
    /// dropped on permanent failure. Once terminated, every call reports the
    /// same outcome.
    pub fn read_with_fds(
        &mut self,
        destination: &mut [u8],
        max_new_fds: usize,
    ) -> Result<ReadWithFdsResult, ShmStreamError> {
        // This entire function implementation is just concerned with turning EPIPE into a
        // zero-length read to signal EOF/shutdown
        match self.read_with_fds_impl(destination, max_new_fds) {
            Ok(v) => Ok(v),
            Err(e) => e.as_external_read_with_fds_result(),
        }
    }

    pub fn read_with_fds_impl(
        &mut self,
        destination: &mut [u8],
        max_new_fds: usize,
    ) -> Result<ReadWithFdsResult, ShmStreamError> {
        use ShmStreamError as S;
        use rustix::io::Errno as E;

        // Previous termination; if we previously terminated, we should
        // report the stream as terminated
        self.ensure_live_for_read()?;

        //  Empty inputs
        if destination.is_empty() {
            return Ok(ReadWithFdsResult::empty());
        }

        // Load the chunk announcement (or do nothing, if we have an announced chunk already)
        let res = self
            .recv_and_register_chunk_announcement(max_new_fds)
            .map_err(|e| e.normalize());

        // Handle errors during IO; differently based on the state we are currently in
        use OperationalStateDiscriminants as D;
        let mut fd_result = match (self.state().discriminant(), res) {
            // Success; store the result so we can return the number of fds (or zero if this is a
            // chunk in progress)
            (_, Ok(r)) => r.unwrap_or_default(),
            // Blocking operation; just interrupted, can continue later
            (D::Normal, Err(S::Io(E::WOULDBLOCK))) => return Err(E::WOULDBLOCK)?,
            // Blocking operation, but we are draining so this shuts the stream down
            (D::Draining, Err(S::Io(E::WOULDBLOCK))) => {
                // Unwrap can't panic, because we KNOW we are in draining stat
                let cached_failure = self.advance_draining_to_terminated().unwrap();
                return Err(cached_failure)?;
            }
            // Other errors are handled normally
            (_, Err(e)) => {
                self.terminate_immediately(e).discard_result();
                return Err(e)?;
            }
        };

        // Actually read the data bytes and update the amount of data read to be the amount of data
        // read from the stream, not from the notification socket
        fd_result.data_read = self.read_chunk_bytes(destination);

        // If we managed to read an entire chunk, we must register it so an appropriate chunk
        // acknowledgement was sent
        if !self.has_partially_read_chunk() {
            *self.pending_ack_count_mut() += 1;
        }

        // Send (possibly more than this one) chunk acknowledgement
        self.service_chunk_acknowledgements().discard_result();

        Ok(fd_result)
    }

    fn recv_and_register_chunk_announcement(
        &mut self,
        max_new_fds: usize,
    ) -> Result<Option<ReadWithFdsResult>, ShmStreamError> {
        // Return early if the last chunk was not fully drained
        if self.has_partially_read_chunk() {
            return Ok(None);
        }

        // Do IO, load the chunk announcement
        let announcement = self.recv_chunk_announcement(max_new_fds)?;

        // Technically fences are not really meant for our system IO based
        // synchronization, but we still include a fence for good measure!
        fence(Ordering::Acquire);

        // Transactionally read the chunk; we restore the value in case of a failure (ring buffer
        // out of bounds) out of politeness; in practice, this is irrelevant through because we
        // terminate the stream immediately in case of an overflow so no further reads can happen
        let pre_transaction_scheduler = self.scheduler().copy();
        run(|| -> Result<(), ShmStreamError> {
            // Read the header and announce the bytes we are gaining
            let payload_len = self
                .announce_and_read_value_from_chunk_bytes::<ChunkHeader>()?
                .payload_len();

            // We do not allow zero-len payloads
            if payload_len == 0 {
                Err(ShmProtocolViolation::InvalidChunkLength)?;
            }

            // Register the chunk bytes with the ring buffer scheduler
            self.announce_chunk_bytes(payload_len)?;

            // There should be at least as many unused bytes in the buffer, as the ChunkHeader is
            // big. Otherwise, there was a buffer overflow just big enough to overflow into the
            // header
            if self.chunk_space_avail() < size_of::<ChunkHeader>() {
                Err(ShmProtocolViolation::ControlOverflow)?;
            }

            Ok(())
        })
        .inspect_err(|_| {
            *self.scheduler_mut() = pre_transaction_scheduler;
        })?;

        // Signal that we have a chunk to the user
        Ok(Some(announcement))
    }

    fn recv_chunk_announcement(
        &mut self,
        max_new_fds: usize,
    ) -> Result<ReadWithFdsResult, ShmStreamError> {
        let mut syn_byte = 0u8;
        let res = handle_interrupted(|| {
            let fd = self.notification_socket();
            let dst = std::slice::from_mut(&mut syn_byte);
            recv_fd_msg(fd, dst, max_new_fds, RecvFlags::DONTWAIT)
                .apply(ShmStreamError::cache_shutdown_as_epipe)
        })?;

        if syn_byte != 0 {
            Err(ShmProtocolViolation::InvalidChunkAnnouncement)?;
        }

        Ok(res)
    }

    fn announce_and_read_value_from_chunk_bytes<T>(&mut self) -> Result<T, ShmStreamError>
    where
        T: IntoBytes + FromBytes + KnownLayout + Immutable + Default,
    {
        let mut t = T::default();
        self.announce_and_read_chunk_bytes(t.as_mut_bytes())?;
        Ok(t)
    }

    fn announce_and_read_chunk_bytes(&mut self, dst: &mut [u8]) -> Result<(), ShmStreamError> {
        self.announce_chunk_bytes(dst.len())
            .map_err(|_| ShmProtocolViolation::ControlOverflow)?;
        self.read_chunk_bytes(dst);
        Ok(())
    }

    fn announce_chunk_bytes(&mut self, cnt: usize) -> Result<(), ShmStreamError> {
        *self.scheduler_mut() = self
            .scheduler()
            .try_register_write(cnt as u64)
            .map_err(|_| ShmProtocolViolation::ControlOverflow)?;
        Ok(())
    }

    fn read_chunk_bytes(&mut self, dst: &mut [u8]) -> usize {
        // Announce the extra data to the scheduler
        let mut sched = self.scheduler().copy();

        // Read data into the given buffer
        let cnt = self.shared().read_from_receiver_buffer(&mut sched, dst);

        // Reset the stored scheduler
        *self.scheduler_mut() = sched;

        // Return the number of bytes read
        cnt
    }

    pub fn service_chunk_acknowledgements(&mut self) -> Result<(), ShmStreamError> {
        self.ensure_live_for_ack_service()?;

        if let Err(reason) = self.flush_chunk_acknowledgements() {
            self.terminate_draining(reason)?;
            return Err(reason);
        };

        Ok(())
    }

    fn flush_chunk_acknowledgements(&mut self) -> Result<(), ShmStreamError> {
        loop {
            let ack_buf = [0u8; 128];
            let batch_size = std::cmp::min(ack_buf.len(), self.pending_ack_count());
            let ack_buf = &ack_buf[..batch_size];

            if ack_buf.is_empty() {
                return Ok(());
            }

            let res = handle_interrupted(|| {
                let fd = self.notification_socket();
                send_fd_msg(fd, ack_buf, &[], SendFlags::DONTWAIT)
            });

            use rustix::io::Errno as E;
            let acks_written = match res.map(NonZero::new) {
                // All good
                Ok(Some(n)) => n.get(),
                // send_fd_msg() returned zero; this is forbidden
                Ok(None) => return Err(E::IO)?,
                // Blocked; return until the stream becomes serviceable again
                #[allow(unreachable_patterns)] // EAGAIN == EWOULDBLOCK on Linux, BSD, macOS
                Err(E::WOULDBLOCK | E::AGAIN) => return Ok(()),
                // Other error
                Err(e) => return Err(e)?,
            };

            *self.pending_ack_count_mut() -= acks_written;
        }
    }

    #[allow(dead_code)] // kept on human request (unused for now)
    pub fn shutdown(&mut self) -> io::Result<()> {
        self.terminate_draining(ShmStreamError::SHUTDOWN)
            .map_err(|e| e.into_stdio_err())
    }

    fn advance_draining_to_terminated(&mut self) -> Result<ShmStreamError, ()> {
        let Some(cached) = self.cached_failure() else {
            return Err(());
        };

        self.terminate_immediately(cached).discard_result();

        Ok(cached)
    }

    /// Refuses to accept WOULDBLOCK and EAGAIN as a failure reason and treats them as Normal-state
    /// instead
    fn terminate_draining(&mut self, reason: ShmStreamError) -> Result<(), rustix::io::Errno> {
        self.advance_operational_state_towards_termination(Draining::new(reason).into())
    }

    /// Refuses to accept WOULDBLOCK and EAGAIN as a failure reason and treats them as Normal-state
    /// instead
    fn terminate_immediately(&mut self, reason: ShmStreamError) -> Result<(), rustix::io::Errno> {
        self.advance_operational_state_towards_termination(Terminated::new(reason).into())
    }

    /// Refuses to accept WOULDBLOCK and EAGAIN as a failure reason and treats them as Normal-state
    /// instead
    fn advance_operational_state_towards_termination(
        &mut self,
        advanced: OperationalState,
    ) -> Result<(), rustix::io::Errno> {
        let advanced = self.state().advance_state_towards_termination(advanced);

        let res = match !advanced.is_normal() {
            true => self.issue_notification_socket_shutdown(),
            false => Ok(()),
        };

        *self.state_mut() = advanced;

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

    fn receiver_mut(&mut self) -> &mut ReceiverState {
        self.receiver.borrow_mut()
    }

    fn scheduler_mut(&mut self) -> &mut RingBufferScheduler {
        self.receiver_mut().scheduler.borrow_mut()
    }

    fn state_mut(&mut self) -> &mut OperationalState {
        self.receiver_mut().state.borrow_mut()
    }

    fn notification_socket_shutdown_issued_mut(&mut self) -> &mut Option<()> {
        self.receiver_mut()
            .notification_socket_shutdown_issued
            .borrow_mut()
    }

    fn pending_ack_count_mut(&mut self) -> &mut usize {
        self.receiver_mut().pending_ack_count.borrow_mut()
    }
}

impl<Shared: Borrow<SharedState>, Receiver: Borrow<ReceiverState>> ReceiverFrame<Shared, Receiver> {
    /// Register the notification socket; readiness is only a retry hint.
    pub fn register(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.receiver.borrow().notification_socket.as_raw_fd())
            .register(registry, token, interests)
    }

    /// Reregister the notification socket.
    pub fn reregister(
        &mut self,
        registry: &mio::Registry,
        token: Token,
        interests: Interest,
    ) -> io::Result<()> {
        SourceFd(&self.receiver.borrow().notification_socket.as_raw_fd())
            .reregister(registry, token, interests)
    }

    /// Deregister the notification socket.
    pub fn deregister(&mut self, registry: &mio::Registry) -> io::Result<()> {
        SourceFd(&self.receiver.borrow().notification_socket.as_raw_fd()).deregister(registry)
    }
}
