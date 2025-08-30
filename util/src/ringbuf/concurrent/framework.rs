//! An implementation of a concurrent ring buffer with the
//! core (IO/memory access) operations in a detached trait. Everything around the core is
//! implemented but before being able to use this, callers must implement an appropriate IO core.

use crate::int::u64uint::U64USizeRangeExt;
use crate::result::OkExt;
use crate::ringbuf::sched::{
    Diff, OperationType, RingBufferFromCountersError, RingBufferScheduler, ScheduledOperations,
};
use crate::sync::atomic::abstract_atomic::AbstractAtomic;

/// Core trait used by [ConcurrentPipeReader] and [ConcurrentPipeWriter] to implement
/// a concurrent pipe based on a ring buffer
pub trait ConcurrentPipeCore {
    /// The type used for the atomics; i.e. the values returned by
    /// [Self::items_read] and [Self.:items_written].
    type AtomicType: AbstractAtomic<u64>;

    /// Length of the underlying memory buffer
    fn buf_len(&self) -> u64;

    /// Number of items read
    fn items_read(&self) -> &Self::AtomicType;
    /// Number of items written
    fn items_written(&self) -> &Self::AtomicType;
    /// Copy data from the underlying memory buffer into the destination
    fn read_from_buffer(&mut self, dst: &mut [u8], off: u64);
    /// Write data from src into the underlying memory buffer
    fn write_to_buffer(&mut self, off: u64, src: &[u8]);
}

/// Raised by [ConcurrentPipeReader::read()]/[ConcurrentPipeWriter::write()] if the underlying
/// ring buffer is in an inconsistent state.
///
/// When used in shared memory applications, this error may have been locally caused, but it may
/// also be caused by **the other threads or processes** putting the ring buffer into an
/// inconsistent state.
///
/// For this reason, you must treat this error as an unrecoverable breakdown of the communication channel. You
/// must close and no longer use ring buffer after receiving this error, but you can handle it
/// gracefully by reopening a new ring buffer in its place.
///
/// # API Stability
///
/// Treat this error type as opaque; do not rely on the enum values remaining the same
#[derive(Debug, thiserror::Error, Clone)]
pub enum InconsistentRingBufferStateError {
    /// Failed to update an inner counter; this probably indicates a data race (forbidden
    /// concurrent read/write)
    #[error("Concurrent access to the ring buffer {:?}", self)]
    ConcurrrentAccess {
        /// Whether this was a read or write
        operation_type: OperationType,
        /// Operations performed before updaing the ring buffer state
        scheduled_ops: ScheduledOperations,
        /// The scheduler that scheduled our operation
        scheduler_state: RingBufferScheduler,
        /// The counter value before compare and exchange
        expected_counter_value: u64,
        /// The counter value we actually found in the counter
        actual_counter_value: u64,
        /// The counter value we tried to set
        new_counter_value_tried_to_set: u64,
    },
    /// Could not construct ring buffer scheduler
    #[error("Inconsistent ring buffer state: {:?}", .0)]
    InconsistentCounterState(#[from] RingBufferFromCountersError),
}

/// Indicator for [ConcurrentPipeImpl::read_or_write] about which operation
/// is being executed
#[derive(Debug)]
enum ConcurrentPipeOperation<'a> {
    /// This call implements [ConcurrentPipeReader::read]
    Read(&'a mut [u8]),
    /// This call implements [ConcurrentPipeReader::write]
    Write(&'a [u8]),
}

impl<'a> ConcurrentPipeOperation<'a> {
    /// Read-only access to the operation buffer
    pub fn inner_buf(&'a self) -> &'a [u8] {
        match self {
            ConcurrentPipeOperation::Read(items) => items,
            ConcurrentPipeOperation::Write(items) => items,
        }
    }

    /// Length of [Self::inner_buf]
    pub fn len(&self) -> usize {
        self.inner_buf().len()
    }

    /// Decides which type of operation, in terms of [OperationType] [Self] represents
    pub fn scheduler_op(&self) -> OperationType {
        match self {
            ConcurrentPipeOperation::Read(_) => OperationType::Read,
            ConcurrentPipeOperation::Write(_) => OperationType::Write,
        }
    }
}

/// The implementations of [ConcurrentPipeReader] and [ConcurrentPipeWriter]
/// happen to be extremely similar. This struct forms the basis of both.
struct ConcurrentPipeImpl<Core: ConcurrentPipeCore> {
    /// Core trait
    core: Core,
}

impl<Core: ConcurrentPipeCore> ConcurrentPipeImpl<Core> {
    /// Like [ConcurrentPipeReader::from_core] and [ConcurrentPipeWriter::from_core]
    fn from_core(core: Core) -> Self {
        Self { core }
    }

    /// The implementations of [ConcurrentPipeReader::read] and [ConcurrentPipeWriter::write]
    /// happen to be extremely similar. This function implements both.
    fn read_or_write(
        &mut self,
        mut op: ConcurrentPipeOperation,
    ) -> Result<usize, InconsistentRingBufferStateError> {
        use std::sync::atomic::Ordering as O;

        // Figure out which counter to store the result of the operation in and the orderings to
        // use for load/store operations
        let (ord_r, ord_w, ord_store_succ, ord_store_fail) = match op {
            ConcurrentPipeOperation::Read(_) => (O::Relaxed, O::Acquire, O::Relaxed, O::Relaxed),
            ConcurrentPipeOperation::Write(_) => (O::Relaxed, O::Relaxed, O::Release, O::Relaxed),
        };

        // Construct a ring buffer scheduler from the current state
        let sched = RingBufferScheduler::try_from_counters(
            self.core.buf_len(),
            self.core.items_written().load(ord_w),
            self.core.items_read().load(ord_r),
        )?;

        // Have the scheduler schedule the operations
        let ops = sched.schedule_contigous_operations(op.scheduler_op(), op.len());

        // Actually perform the operations
        for (buf_slice, ring_op) in ops.with_outside_buffer_range() {
            match &mut op {
                ConcurrentPipeOperation::Read(dst) => self
                    .core
                    .read_from_buffer(&mut dst[buf_slice.usize()], ring_op.off),
                ConcurrentPipeOperation::Write(src) => self
                    .core
                    .write_to_buffer(ring_op.off, &src[buf_slice.usize()]),
            }
        }

        // Take a differential between the scheduler and the scheduler after the operations where
        // applied. Make sure only one counter was updated
        let diff = sched
            .register_operation(&ops)
            .diff_old(&sched)
            .expect_op_only(op.scheduler_op())
            .unwrap();

        let store_to_ctr = match op {
            ConcurrentPipeOperation::Read(_) => self.core.items_read(),
            ConcurrentPipeOperation::Write(_) => self.core.items_written(),
        };

        // Update the counters, assuming there was any change at all
        if let Diff::Different(old, new) = diff {
            store_to_ctr
                .compare_exchange(old, new, ord_store_succ, ord_store_fail)
                .map_err(
                    |actual| InconsistentRingBufferStateError::ConcurrrentAccess {
                        operation_type: op.scheduler_op(),
                        scheduled_ops: ops,
                        scheduler_state: sched,
                        expected_counter_value: old,
                        actual_counter_value: actual,
                        new_counter_value_tried_to_set: new,
                    },
                )?;
        }

        ops.cumulative_operation_length().usize().ok()
    }
}

/// Provides the necessary boilerplate around [ConcurrentPipeCore] to implement
/// reading from the pipe
pub struct ConcurrentPipeReader<Core: ConcurrentPipeCore> {
    /// The implementations of [ConcurrentPipeReader::read] and [ConcurrentPipeWriter::write]
    /// happen to be extremely similar. We use [ConcurrentPipeImpl] to implement both.
    inner: ConcurrentPipeImpl<Core>,
}

impl<Core: ConcurrentPipeCore> ConcurrentPipeWriter<Core> {
    /// Create a [Self] from a [ConcurrentPipeCore]
    pub fn from_core(core: Core) -> Self {
        Self {
            inner: ConcurrentPipeImpl::from_core(core),
        }
    }

    /// Determine the length of the underlying ring buffer
    pub fn buf_len(&self) -> u64 {
        self.inner.core.buf_len()
    }

    /// Write data into the concurrent pipe.
    ///
    /// Returns the number of bytes actually written.
    pub fn write(&mut self, src: &[u8]) -> Result<usize, InconsistentRingBufferStateError> {
        self.inner
            .read_or_write(ConcurrentPipeOperation::Write(src))
    }
}

/// Provides the necessary boilerplate around [ConcurrentPipeCore] to implement
/// writing to the pipe
pub struct ConcurrentPipeWriter<Core: ConcurrentPipeCore> {
    /// The implementations of [ConcurrentPipeReader::read] and [ConcurrentPipeWriter::write]
    /// happen to be extremely similar. We use [ConcurrentPipeImpl] to implement both.
    inner: ConcurrentPipeImpl<Core>,
}

impl<Core: ConcurrentPipeCore> ConcurrentPipeReader<Core> {
    /// Create a [Self] from a [ConcurrentPipeCore]
    pub fn from_core(core: Core) -> Self {
        Self {
            inner: ConcurrentPipeImpl::from_core(core),
        }
    }

    /// Determine the length of the underlying ring buffer
    pub fn buf_len(&self) -> u64 {
        self.inner.core.buf_len()
    }

    /// Read data from the concurrent pipe.
    ///
    /// Returns the number of bytes read.
    pub fn read(&mut self, dst: &mut [u8]) -> Result<usize, InconsistentRingBufferStateError> {
        self.inner.read_or_write(ConcurrentPipeOperation::Read(dst))
    }
}
