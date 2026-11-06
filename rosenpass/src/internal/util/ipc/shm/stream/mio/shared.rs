//! Protected mapping, directional offsets and bounded volatile copies.

use zerocopy::{
    FromBytes, Immutable, IntoBytes, KnownLayout, byteorder::little_endian::U32 as LittleEndianU32,
};

use super::{MAX_SHM_BUF_LEN, MIN_SHM_BUF_LEN, RingLayout, SharedMemorySegment};
use crate::internal::util::{
    ipc::shm::stream::mio::ShmStreamCreationError, ringbuf::sched::RingBufferScheduler,
};

/// Error used to signal shutdown/eof both on the sender side
/// and on the receiver side.
///
/// sendmsg(2)/[crate::internal::util::io::fd_stream::send_fd_msg]/[crate::internal::util::io::fd_stream::FdPassingStream::write_with_fds] actually
/// do send EPIPE on Eof (shutdown or when the FD was closed on the other end without draining
/// first), but recvmsg(2)/[crate::internal::util::io::fd_stream::recv_fd_msg]/[crate::internal::util::io::fd_stream::FdPassingStream::read_with_fds]
/// does not; instead the reader/receiving end just returns a zero-sized read. The receiving side
/// should never actually return EPIPE.
///
/// We use EPIPE both in both directions to signal/cache a shutdown/EOF scenarios as
/// [super::ShmStreamError::Io] with EPIPE, but on the receiving direction, we
/// we turn this into a zero sized read again
pub const SHUTDOWN_ERRNO: rustix::io::Errno = rustix::io::Errno::PIPE;

/// Native-endian payload length
pub type ChunkLenPrefix = u32;

/// Header for transmitted chunks
#[repr(C)]
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, IntoBytes, FromBytes, KnownLayout, Immutable, Default,
)]
pub struct ChunkHeader {
    /// Payload bytes following this prefix, little-endian on the ring.
    payload_len: zerocopy::little_endian::U32,
}

impl ChunkHeader {
    /// Encode the header of a chunk carrying `payload_len` payload bytes.
    pub fn new(payload_len: ChunkLenPrefix) -> Self {
        Self {
            payload_len: LittleEndianU32::new(payload_len),
        }
    }

    /// Panics if the given value is too big
    pub fn new_from_usize(payload_len: usize) -> Self {
        Self::new(payload_len.try_into().unwrap())
    }

    /// Payload length decoded from this owned header snapshot.
    pub fn payload_len(&self) -> usize {
        self.payload_len.get() as usize
    }
}

/// Check that a shared buffer of `len` bytes has an even length within the supported ring sizes
pub fn validate_buffer_geometry(len: usize) -> Result<(), ShmStreamCreationError> {
    use ShmStreamCreationError as E;

    if !len.is_multiple_of(2) {
        return Err(E::InvalidMappingLength);
    } else if !(MIN_SHM_BUF_LEN..=MAX_SHM_BUF_LEN).contains(&len) {
        return Err(E::InvalidRingSize);
    }

    Ok(())
}

#[derive(Debug)]
pub struct SharedState {
    segment: SharedMemorySegment,
    layout: RingLayout,
}

impl SharedState {
    /// Constructor
    pub fn new(
        segment: SharedMemorySegment,
        layout: RingLayout,
    ) -> Result<Self, ShmStreamCreationError> {
        validate_buffer_geometry(segment.len())?;
        Ok(Self { segment, layout })
    }

    /// Byte capacity of each equal-sized directional ring.
    pub fn ring_capacity(&self) -> usize {
        self.segment.len() / 2
    }

    /// Byte offset of the incoming payload ring within the mapping.
    pub fn receiver_buffer_off(&self) -> usize {
        match self.layout {
            RingLayout::LowSendHighReceive => self.ring_capacity(),
            RingLayout::LowReceiveHighSend => 0,
        }
    }

    /// Byte offset of the outgoing payload ring within the mapping.
    pub fn sender_buffer_off(&self) -> usize {
        match self.layout {
            RingLayout::LowSendHighReceive => 0,
            RingLayout::LowReceiveHighSend => self.ring_capacity(),
        }
    }

    pub fn read_from_receiver_buffer(
        &self,
        scheduler: &mut RingBufferScheduler,
        destination: &mut [u8],
    ) -> usize {
        let ops = scheduler.schedule_reads(destination.len());
        for (outside, op) in ops.with_outside_buffer_range() {
            let op_off = usize::try_from(op.off).unwrap();
            let offset = self.receiver_buffer_off().checked_add(op_off).unwrap();

            self.segment.volatile_read(
                &mut destination[outside.start.usize()..outside.end.usize()],
                offset,
            );
        }
        *scheduler = scheduler.register_operation(&ops);

        ops.cumulative_operation_length().usize()
    }

    pub fn write_to_sender_buffer(
        &self,
        scheduler: &mut RingBufferScheduler,
        source: &[u8],
    ) -> usize {
        let ops = scheduler.schedule_writes(source.len());
        for (outside, op) in ops.with_outside_buffer_range() {
            let op_off = usize::try_from(op.off).expect("ring offset fits usize");
            let offset = self
                .sender_buffer_off()
                .checked_add(op_off)
                .expect("two bounded rings");
            self.segment
                .volatile_write(offset, &source[outside.start.usize()..outside.end.usize()]);
        }
        *scheduler = scheduler.register_operation(&ops);

        ops.cumulative_operation_length().usize()
    }
}
