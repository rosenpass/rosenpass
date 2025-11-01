//! Shared-memory ring buffer implementations (main part of the enclosing module)

use std::{borrow::Borrow, sync::atomic::AtomicU64};

use zerocopy::{FromBytes, IntoBytes};

use crate::{
    ipc::shm::SharedMemorySegment,
    ringbuf::concurrent::framework::{
        ConcurrentPipeCore, ConcurrentPipeReader, ConcurrentPipeWriter,
    },
};

/// Synchronization variables for a [ShmPipeWriter]/[ShmPipeReader].
///
/// These values must be shared between the reader/writer in such a way that access to the inner
/// variables is synchronized and atomic between the two parties.
#[repr(C)]
#[derive(Debug, Default, IntoBytes, FromBytes)]
pub struct ShmPipeVariables {
    /// See [crate::ringbuf::sched::RingBufferScheduler::items_read()]
    pub items_read: AtomicU64,
    /// See [crate::ringbuf::sched::RingBufferScheduler::items_written()]
    pub items_written: AtomicU64,
}

impl ShmPipeVariables {
    /// Constructor
    pub fn new() -> Self {
        Self {
            items_read: 0.into(),
            items_written: 0.into(),
        }
    }
}

/// The [ConcurrentPipeCore] for a shared memory pipe.
#[derive(Debug)]
pub struct ShmPipeCore<Variables: Borrow<ShmPipeVariables>> {
    /// The synchronization variables
    variables: Variables,
    /// The memory buffer
    buf: SharedMemorySegment,
}

impl<Variables: Borrow<ShmPipeVariables>> ShmPipeCore<Variables> {
    /// Constructor
    pub fn new(variables: Variables, buf: SharedMemorySegment) -> Self {
        Self { variables, buf }
    }
}

/// A shared memory pipe reader
pub type ShmPipeReader<Variables> = ConcurrentPipeReader<ShmPipeCore<Variables>>;

/// A shared memory pipe reader
pub type ShmPipeWriter<Variables> = ConcurrentPipeWriter<ShmPipeCore<Variables>>;

impl<Variables: Borrow<ShmPipeVariables>> ConcurrentPipeCore for ShmPipeCore<Variables> {
    type AtomicType = AtomicU64;

    fn buf_len(&self) -> u64 {
        self.buf.len() as u64
    }

    fn items_read(&self) -> &AtomicU64 {
        &self.variables.borrow().items_read
    }

    fn items_written(&self) -> &AtomicU64 {
        &self.variables.borrow().items_written
    }

    fn read_from_buffer(&mut self, dst: &mut [u8], off: u64) {
        self.buf.volatile_read(dst, off as usize)
    }

    fn write_to_buffer(&mut self, off: u64, src: &[u8]) {
        self.buf.volatile_write(off as usize, src);
    }
}
