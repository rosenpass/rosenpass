//! Contains [RingBufferScheduler], which does not actually implement a ring buffer, but which
//! handles the complicated math involved in writing/reading to a ring buffer backed by a linear
//! memory array

use std::borrow::Borrow;

use crate::{
    functional::{ApplyExt, MutatingExt},
    int::modular::Modulus,
    int::u64uint::{TruncateIntoU64USize, U64USize, U64USizeConversionError},
    mem::{CopyExt, MutateRefExt},
    result::OkExt,
};

/// Boolean numbers, named "Zero" and "One" for clarity
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bit {
    /// Zero <=> False
    Zero,
    /// One <=> True
    One,
}

/// Type of a block in a ring buffer. Can either be occupied or not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BlockType {
    /// The block does not contain data
    Free,
    /// The block does contain data
    Data,
}

/// Distinguishes Read & Write operations
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationType {
    /// Read from the ring buffer
    Read,
    /// Write to the ring buffer
    Write,
}

/// Identifying information about a block in a ring buffer
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Block {
    /// What sort of block this is
    pub typ: BlockType,
    /// The index; together with `typ` this uniquely identifies a block.
    /// A block `no = Zero, typ = Free` would be the first empty block in
    /// a ring buffer. `no = One, typ = Data` would be the second data-filled block
    pub no: Bit,
    /// Where the block begins
    pub off: u64,
    /// How long the block is
    pub len: u64,
}

impl Block {
    /// Constructor
    pub fn new(typ: BlockType, no: Bit, off: u64, len: u64) -> Self {
        Self { typ, no, off, len }
    }
}

/// According to the write/read offsets, a buffer can use one of two layouts
///
/// Layout 1:
///
/// ```txt
/// Data | Free | Data
/// ```
///
/// Layout 2:
///
/// ```txt
/// Free | Data | Free
/// ```
///
/// For details about how the layout is determined, please
/// see the source code of [RingBufferScheduler::layout].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferLayout {
    /// Layout is `Data | Free | Data`
    DataFreeData,
    /// Layout is `Free | Data | Free`
    FreeDataFree,
}

/// Fill state of the ring buffer
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum BufferFillState {
    /// Entirely empty
    Empty,
    /// Part empty, part filled
    Partial,
    /// Entirely filled
    Full,
}

/// Operations that can be passed to [RingBufferScheduler::try_register_operation]
pub trait RegisterableOperation {
    /// Error type returned in case of failure
    type Error: std::fmt::Debug;
    /// Register this operation with a ring buffer
    fn register(&self, ring: RingBufferScheduler) -> Result<RingBufferScheduler, Self::Error>;
}

/// A scheduled operation on the ring buffer.
///
/// This is returned by [RingBufferScheduler::schedule_reads]/[RingBufferScheduler::schedule_writes]
/// in an array and essentially just represents a slice in the ring buffer.
///
/// Also see [ScheduledOperationContainerExt] which offers operations on the whole array of
/// operations returned by the ring buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScheduledOperation {
    /// A hint, about whether this operation is a read or a write
    pub typ: OperationType,
    /// Ring buffer offset, where the operation should start
    pub off: u64,
    /// After how many items the operation should end
    pub len: U64USize,
}

/// We need default for [tinyvec::ArrayVec] to work
impl Default for ScheduledOperation {
    fn default() -> Self {
        Self::new(OperationType::Read, Default::default(), Default::default())
    }
}

impl ScheduledOperation {
    /// Constructor
    pub fn new(typ: OperationType, off: u64, len: U64USize) -> Self {
        Self { typ, off, len }
    }
}

impl RegisterableOperation for ScheduledOperation {
    type Error = RingBufferRegisterOpError;

    fn register(&self, ring: RingBufferScheduler) -> Result<RingBufferScheduler, Self::Error> {
        ring.try_register_operation_manually(self.typ, self.len.u64())
    }
}

/// Error returned by [ScheduledOperations::try_new]
#[derive(thiserror::Error, Debug)]
pub enum ScheduledOperationCreationError {
    /// Cause of this error
    #[error("Could not create ScheduledOperations (list of ScheduledOperation); cumulative operation length too long: {:?}", .0)]
    SizeConversionError(#[from] U64USizeConversionError<u64>),
    /// The operations are not all of the same type
    #[error("Could not create ScheduledOperations (list of ScheduledOperation); inconsistent operation type (read/write)")]
    InconsistentOperationType,
}

/// The type returned by [RingBufferScheduler::schedule_contigous_operations()] and sister
/// functions.
pub type ScheduledOperations =
    AbstractScheduledOperations<tinyvec::ArrayVec<[ScheduledOperation; 2]>>;

/// Represents a list of [ScheduledOperation]s, while enforcing that the total operation
/// length can be represented both as a u64 and as a usize and that all the operation types
/// (read/write) are the same.
///
/// This is the abstract type that supports many different containers. The concrete type
/// represented by [RingBufferScheduler::schedule_contigous_operations()] and sister methods
/// is [ScheduledOperations].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AbstractScheduledOperations<Cont>
where
    Cont: IntoIterator<Item = ScheduledOperation>,
    for<'a> &'a Cont: IntoIterator<Item = &'a ScheduledOperation>,
    for<'a> &'a mut Cont: IntoIterator<Item = &'a mut ScheduledOperation>,
{
    /// Inner range
    cont: Cont,
}

impl<Cont> RegisterableOperation for AbstractScheduledOperations<Cont>
where
    Cont: IntoIterator<Item = ScheduledOperation>,
    for<'a> &'a Cont: IntoIterator<Item = &'a ScheduledOperation>,
    for<'a> &'a mut Cont: IntoIterator<Item = &'a mut ScheduledOperation>,
{
    type Error = RingBufferRegisterOpError;

    fn register(&self, ring: RingBufferScheduler) -> Result<RingBufferScheduler, Self::Error> {
        self.container()
            .into_iter()
            .try_fold(ring, |ring, op| ring.try_register_operation(op))
    }
}

impl<Cont> AbstractScheduledOperations<Cont>
where
    Cont: IntoIterator<Item = ScheduledOperation>,
    for<'a> &'a Cont: IntoIterator<Item = &'a ScheduledOperation>,
    for<'a> &'a mut Cont: IntoIterator<Item = &'a mut ScheduledOperation>,
{
    /// Ensure this ScheduledOperations is in a sound in a sound state
    fn demand_soundness(&self) -> Result<(), ScheduledOperationCreationError> {
        use ScheduledOperationCreationError as E;

        // Ensure that the operation length is representable as usize & u64
        U64USize::try_new(self.cumulative_operation_length_u64())?;

        // Ensure that the operation type is the same across all operations
        self.container()
            .into_iter()
            .map(|op| op.typ)
            .map(Some)
            .reduce(|acc, elm| (acc == elm).then_some(()).and(acc))
            .map(|v| v.is_some())
            .unwrap_or(true)
            .then_some(())
            .ok_or(E::InconsistentOperationType)?;

        Ok(())
    }

    /// Create a new list of scheduled operations
    pub fn try_new(cont: Cont) -> Result<Self, ScheduledOperationCreationError> {
        let me = Self { cont };
        me.demand_soundness()?;
        Ok(me)
    }

    /// Like [Self::try_new], but panics on error
    pub fn new_or_panic(cont: Cont) -> Self {
        match Self::try_new(cont) {
            Ok(v) => v,
            Err(e) => panic!("{e:?}"),
        }
    }

    /// Access to the inner container
    pub fn container(&self) -> &Cont {
        self.cont.borrow()
    }

    /// Extract the inner container
    pub fn into_container(self) -> Cont {
        self.cont
    }

    /// Used by [Self::try_new] and [Self::cumulative_operation_length]
    fn cumulative_operation_length_u64(&self) -> u64 {
        // Won't panic, because we ensure that the cumulative length is short enough
        // upon creation of Self
        self.cont
            .borrow()
            .into_iter()
            .map(|op| op.len.u64())
            .fold(0u64, std::ops::Add::add)
    }

    /// Sum of all the operation lengths in the list.
    ///
    /// This would be the total number of bytes written/read if all of the operations where
    /// applied.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::ringbuf::sched::{AbstractScheduledOperations, ScheduledOperation, OperationType};
    ///
    /// use OperationType::Read as R;
    ///
    /// let inp = AbstractScheduledOperations::new_or_panic(vec![
    ///     ScheduledOperation::new(R, 8, 1u8.into()),
    ///     ScheduledOperation::new(R, 22, 10u8.into()),
    ///     ScheduledOperation::new(R, 1000, 100u8.into()),
    /// ]);
    ///
    /// assert_eq!(inp.cumulative_operation_length(), 111u8.into());
    /// ```
    pub fn cumulative_operation_length(&self) -> U64USize {
        // Won't panic, because we ensure that the cumulative length is short enough
        // upon creation of Self
        self.cumulative_operation_length_u64()
            .apply(U64USize::new_or_panic)
    }

    /// Sum of the operation lengths before an operation, for each operation.
    ///
    /// In an operation between a linear buffer and a ring buffer, this represents offset in
    /// the linear buffer where the operation would start.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::ringbuf::sched::{AbstractScheduledOperations, ScheduledOperation, OperationType};
    ///
    /// use OperationType::Read as R;
    ///
    /// let inp = AbstractScheduledOperations::new_or_panic(vec![
    ///     ScheduledOperation::new(R, 8, 1u8.into()),
    ///     ScheduledOperation::new(R, 22, 10u8.into()),
    ///     ScheduledOperation::new(R, 1000, 100u8.into()),
    /// ]);
    ///
    /// let cor = vec![
    ///     (0,  ScheduledOperation::new(R, 8, 1u8.into())),
    ///     (1,  ScheduledOperation::new(R, 22, 10u8.into())),
    ///     (11, ScheduledOperation::new(R, 1000, 100u8.into())),
    /// ];
    ///
    /// let out : Vec<(u64, ScheduledOperation)> = inp.with_cumulative_offset()
    ///     .into_iter()
    ///     .map(|(off, op)| (off.u64(), *op))
    ///     .collect();
    ///
    /// assert_eq!(cor, out);
    /// ```
    pub fn with_cumulative_offset(
        &self,
    ) -> impl IntoIterator<Item = (U64USize, &ScheduledOperation)> {
        // Won't panic, because we ensure that the cumulative length is short enough
        // upon creation of Self
        let mut cumulative_offset = 0;
        self.cont.borrow().into_iter().map(move |op| {
            let result = (U64USize::new_or_panic(cumulative_offset), op);
            cumulative_offset += op.len.u64();
            result
        })
    }

    /// Prepares operations between a ring buffer and a linear slice of memory.
    ///
    /// Returns tuples where
    ///
    /// 1. the first element represents the subslice of the linear memory slice
    /// 2. the second element represents the subslice of the ring buffer
    ///
    /// You can work with the `std::ops::Range<`[U64USize]`>` ranges easily by utilizing
    /// [crate::int::U64USizeRangeExt].
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass_util::int::u64uint::U64USize;
    /// use rosenpass_util::ringbuf::sched::{OperationType, ScheduledOperation, ScheduledOperations};
    ///
    /// use tinyvec::ArrayVec;
    ///
    /// use std::ops::Range;
    ///
    /// fn op(off: u64, len: u64) -> ScheduledOperation {
    ///     ScheduledOperation::new(OperationType::Read, off, len.try_into().unwrap())
    /// }
    ///
    /// fn range(start: u64, end: u64) -> Range<U64USize> {
    ///     Range {
    ///         start: start.try_into().unwrap(),
    ///         end: end.try_into().unwrap(),
    ///     }
    /// }
    ///
    /// let inp =
    ///     ScheduledOperations::new_or_panic(ArrayVec::from([op(8, 1), op(22, 10)]));
    ///
    /// let outp: Vec<(Range<U64USize>, ScheduledOperation)> = vec![
    ///     (range(0, 1), op(8, 1)),
    ///     (range(1, 11), op(22, 10)),
    /// ];
    ///
    /// let out: Vec<(Range<U64USize>, ScheduledOperation)> = inp
    ///     .with_outside_buffer_range()
    ///     .into_iter()
    ///     .map(|(range, op)| (range, *op))
    ///     .collect();
    ///
    /// assert_eq!(outp, out);
    /// ```
    pub fn with_outside_buffer_range(
        &self,
    ) -> impl IntoIterator<Item = (std::ops::Range<U64USize>, &ScheduledOperation)> {
        self.with_cumulative_offset()
            .into_iter()
            .map(|(cumul_off, op)| {
                let range = std::ops::Range::<U64USize> {
                    start: cumul_off,
                    // Can not panic, because we checked that the value is
                    // representable in [Self::demand_soundness]
                    end: cumul_off + op.len,
                };
                (range, op)
            })
    }
}

/// Represent the information of whether two values are the same or different
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Diff<T: PartialEq> {
    /// The two values are the same
    Same(T),
    /// The two values are different
    Different(T, T),
}

impl<T: PartialEq> Diff<T> {
    /// Constructor
    pub fn new(old: T, new: T) -> Self {
        match old == new {
            true => Self::Same(old),
            false => Self::Different(old, new),
        }
    }

    /// Whether this enum is [Diff::Same]
    pub fn is_same(&self) -> bool {
        matches!(self, Self::Same(_))
    }

    /// Whether this enum is [Diff::Different]
    pub fn is_different(&self) -> bool {
        matches!(self, Self::Different(_, _))
    }

    /// Return the old value
    pub fn old_value(self) -> T {
        match self {
            Diff::Same(v) => v,
            Diff::Different(old, _) => old,
        }
    }

    /// Return the new value
    pub fn new_value(self) -> T {
        match self {
            Diff::Same(v) => v,
            Diff::Different(_, new) => new,
        }
    }
}

/// Represents a differential over two [RingBufferScheduler]s
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingBufferSchedulerDiff {
    /// How [RingBufferScheduler::buf_len()] changed
    pub buf_len: Diff<u64>,
    /// How [RingBufferScheduler::items_read()] changed
    pub items_read: Diff<u64>,
    /// How [RingBufferScheduler::items_written()] changed
    pub items_written: Diff<u64>,
}

/// Returned by [RingBufferSchedulerDiff::expect_read_only()]
#[derive(thiserror::Error, Debug)]
#[error("Expected ring buffer scheduler diff to only contain a change in the number of items read, but the actual diff is: {diff:?}")]
pub struct RingBufferSchedulerDiffExpectReadOnlyError {
    /// Full differential
    pub diff: RingBufferSchedulerDiff,
}

/// Returned by [RingBufferSchedulerDiff::expect_write_only()]
#[derive(thiserror::Error, Debug)]
#[error("Expected ring buffer scheduler diff to only contain a change in the number of items read, but the actual diff is: {diff:?}")]
pub struct RingBufferSchedulerDiffExpectWriteOnlyError {
    /// Full differential
    pub diff: RingBufferSchedulerDiff,
}

/// Returned by [RingBufferSchedulerDiff::expect_op_only()]
#[derive(thiserror::Error, Debug)]
pub enum RingBufferSchedulerDiffExpectOpOnlyError {
    /// Expands into [RingBufferSchedulerDiffExpectReadOnlyError]
    #[error("{:?}", 0)]
    ReadOnlyError(#[from] RingBufferSchedulerDiffExpectReadOnlyError),
    /// Expands into [RingBufferSchedulerDiffExpectWriteOnlyError]
    #[error("{:?}", 0)]
    WriteOnlyError(#[from] RingBufferSchedulerDiffExpectWriteOnlyError),
}

impl RingBufferSchedulerDiff {
    /// Constructor
    pub fn new(a: RingBufferScheduler, b: RingBufferScheduler) -> Self {
        Self {
            buf_len: Diff::new(a.buf_len(), b.buf_len()),
            items_read: Diff::new(a.items_read(), b.items_read()),
            items_written: Diff::new(a.items_written(), b.items_written()),
        }
    }

    /// Ensure that only the number of items read has changed and return the value
    pub fn expect_read_only(self) -> Result<Diff<u64>, RingBufferSchedulerDiffExpectReadOnlyError> {
        (self.buf_len.is_same() && self.items_written.is_same())
            .then_some(())
            .ok_or(RingBufferSchedulerDiffExpectReadOnlyError { diff: self })?;
        Ok(self.items_read)
    }

    /// Ensure that only the number of items written has changed and return the value
    pub fn expect_write_only(
        self,
    ) -> Result<Diff<u64>, RingBufferSchedulerDiffExpectWriteOnlyError> {
        (self.buf_len.is_same() && self.items_read.is_same())
            .then_some(())
            .ok_or(RingBufferSchedulerDiffExpectWriteOnlyError { diff: self })?;
        Ok(self.items_written)
    }

    /// Call [Self::expect_read_only]/[Self::expect_write_only] as indicated by the operation type
    pub fn expect_op_only(
        self,
        op: OperationType,
    ) -> Result<Diff<u64>, RingBufferSchedulerDiffExpectOpOnlyError> {
        match op {
            OperationType::Read => self.expect_read_only()?.ok(),
            OperationType::Write => self.expect_write_only()?.ok(),
        }
    }
}

/// Handles the math involved in treating a linear slice of memory as a ring buffer.
///
/// The implementation supports buffers up to [Self::MAX_BUF_LEN] in size and handles arbitrarily
/// sized buffers (there is no need to have the buffer size be a multiple of two). We are making no
/// assumption about what sort of items are being transported. It could be bytes, could also be
/// something else.
///
/// This is not necessarily a long-lived structure. There is nothing incorrect about constructing
/// a scheduler on every function call (or read or write) operation in your ring buffer. The
/// structure is completely defined by the values passed to [Self::new].
///
/// Most of the functions provided are used internally and may be of use to the users of the
/// scheduler. The following operations are essential:
///
/// - [Self::new] – Create a new scheduler
/// - [Self::register_write] – Call after actually performing a write to inform the scheduler
///   about how much data was written
/// - [Self::register_read] – Call after actually performing a read to inform the scheduler
///   about how much data has bean read
/// - [Self::schedule_next_read] – Schedule a single, contiguous read from the buffer
/// - [Self::schedule_next_write] – Schedule a single, contiguous write to the buffer
/// - [Self::schedule_reads]/[Self::schedule_writes] – Schedule multiple contiguous reads/writes;
///   as many as are possible
///
/// Internally, the ring buffer stores three values:
///
/// - [Self::buf_len()] – The buffer length
/// - [Self::items_read()] – Number of items read (read offset)
/// - [Self::items_written()] – Number of items written (write offset)
///
/// ## Size Representation
///
/// For the sake of simplicity, [Self] represents all sizes as u64 internally and expects counters
/// to be managed as u64 values.
///
/// To make sure, that the scheduler is still usable on systems where usize is not 64 bit long,
/// the functions scheduling operations (e.g. [Self::schedule_contigous_operations]) never schedule
/// any operations which are too long to be represented as both [u64] and [usize]; this limits
/// operation size to around 4GB on 32 bit systems.
///
/// [Self] agressively uses [U64USize] in various APIs, to make the size requirements and behavior
/// explicit. E.g. [ScheduledOperation::off] is u64, since it refers to positions in the linear
/// buffer underlying the ring buffer while [ScheduledOperation::len] uses [U64USize], because it
/// refers to the operation length, which must always fit into [usize] and [u64].
///
/// Note that [ScheduledOperation::off] being a [u64] is a minor issue. Users of this scheduler can
/// make sure that this offset always fits into a [usize] by choosing a buffer length that fits
/// into [usize].
///
/// ## Counter representations
///
/// The counters ([Self::items_read], [Self::items_written]) are elements of $ℤ_{2 \cdot \texttt{buf_len}}$ (i.e. the
/// integers modulo `2 * buf_len` such that
///
/// ```rust,ignore
/// items_written - items_read <= buf_len
/// ```
///
/// , but they are represented as u64 internally.
///
/// This representation is quite convenient for concurrent ring buffers, as it makes sure that
/// read operations and write operations never need to update the same values. Write operations
/// just update items_written and read operations update items_read through modular addition each.
///
/// In this representation, all possible fill states have a clear representation
///
/// ```rust,ignore
/// data_avail = items_written - items_read
/// space_avail = buf_len - (data_avail)
/// is_empty => data_avail = 0, space_avail = buf_len
/// is_full  => data_avail = buf_len, space_avail = 0
/// ```
///
/// These counters are monotonically increasing; although because we are
/// using modular addition the values often decrease when viewed as plain integers. When using these numbers
/// to derive buffer offsets ([Self::read_off], [Self::write_off]), the scheduler just takes the
/// number of items written/read modulo the buffer length:
///
/// ```rust,ignore
/// read_off = items_read % buf_len
/// write_off = items_written % buf_len
/// ```
///
/// This representation als makes sure we can handle all allowed buffer sizes with ease.
///
/// ## Contiguous data blocks
///
/// The scheduler separates the ring buffer into three regions we call blocks:
///
/// ```txt
/// Block 0 | Block 1 | Block 2
/// ```
///
/// Depending on the number of items written/read, there are four layouts:
///
/// Layout 1 (Partially filled, `read_off < write_off`):
///
/// ```txt
///       Block 0       |       Block 1       |       Block 2
/// Write/Free Block 1  | Read/Filled Block 0 | Write/Free Block 0
/// POSSIBLY ZERO SIZED |                    |  NEVER ZERO SIZED
///                   read_off            write_off
/// ```
///
/// Layout 2 (Partially filled, `write_off < read_off`):
///
/// ```txt
///       Block 0       |       Block 1      |       Block 2
/// Read/Filled Block 1 | Write/Free Block 0 | Read/Filled Block 0
/// POSSIBLY ZERO SIZED |                    |  NEVER ZERO SIZED
///                   write_off           read_off
/// ```
///
/// Layout 3 (Filled):
///
/// ```txt
///       Block 0       |       Block 1        |       Block 2
/// Read/Filled Block 1 |  Write/Empty Block 0 | Read/Filled Block 0
/// POSSIBLY ZERO SIZED |     ZERO SIZED       |  NEVER ZERO SIZED
///                   write_off             read_off
/// ```
///
/// Layout 3 (Empty):
///
/// ```txt
///       Block 0       |       Block 1        |       Block 2
/// Write/Empty Block 1 |  Read/Filled Block 0 | Write/Empty Block 0
/// POSSIBLY ZERO SIZED |     ZERO SIZED       |  NEVER ZERO SIZED
///                   read_off             write_off
/// ```
///
/// The layout used can be determined with [Self::layout()].
///
/// Note that Block 0, i.e. Empty Block 1 or Filled Block 1 is never actually used for any
/// operations. This is not a problem, because filling up Block 2 will just flip the entire
/// ring buffer into the other layout: Block 1 becomes Block 2, Block 0 becomes Block 1 and
/// Block 2 becomes Block 0 which is not zero-sized. Take this example:
///
/// ```txt
/// buf_len = 100
/// items_read = 120
/// items_written = 180
///
/// read_off  = items_read    % buf_len = 120 % 100 = 20
/// write_off = items_written % buf_len = 180 % 100 = 80
///
/// layout = FreeDataFree
///
/// |       Block 0       |       Block 1        |       Block 2    |
/// |        Free         |        Data          |        Free      |
/// |      (20 items)     |      (60 items)      |      (20 items)  |
///
///               read_off = 20             write_off = 80
/// ```
///
/// Block 2 can now be filled by writing 20 items. After this write, the buffer
/// will be in the following state:
///
/// ```txt
/// buf_len = 100
/// items_read = 120
/// items_written = 200
///
/// read_off  = items_read    % buf_len = 120 % 100 = 20
/// write_off = items_written % buf_len = 200 % 100 = 0
///
/// layout = DataFreeData
///
/// |       Block 0       |       Block 1        |       Block 2    |
/// |        Data         |        Free          |        Data      |
/// |      (0 items)      |      (20 items)      |      (60 items)  |
///
///               write_off = 0             read_off = 20
/// ```
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct RingBufferScheduler {
    /// Length of the ring buffer
    buf_len: u64,
    /// Read offset (is not reset and can be bigger than the buffer length)
    items_read: u64,
    /// Write offset (is not reset; routinely bigger than the buffer length and reduced through
    /// modulo)
    items_written: u64,
}
/// Error produced by [RingBufferScheduler::try_new]
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum RingBufferNewError {
    /// The buffer size is too large. This means an extremely large buffer (> 1<<63) is being
    /// managed. What year is this? :)
    #[error("Requested buffer size ({}) is too large. Maximum supported buffer size is (1<<63 = {})", .0, RingBufferScheduler::MAX_BUF_LEN)]
    BufferTooLarge(u64),
}

/// Error produced by [RingBufferScheduler::try_from_counters]
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum RingBufferFromCountersError {
    /// The buffer size is too large. This means an extremely large buffer (> 1<<63) is being
    /// managed. What year is this? :)
    #[error("{:0}", .0)]
    RingBufferNewError(#[from] RingBufferNewError),
    /// items_written >= 2*buf_len
    #[error("For a ring buffer of length {buf_len}, \
        items_written must be < {bl2}, but the actual value is {items_written}",
        bl2 = buf_len*2)]
    ItemsWrittenOutOfBounds {
        /// buf_len parameter
        buf_len: u64,
        /// items_written parameter
        items_written: u64,
    },
    /// items_read >= 2*buf_len
    #[error("For a ring buffer of length {buf_len}, \
        items_read must be < {bl2}, but the actual value is {items_read}",
        bl2 = buf_len*2)]
    ItemsReadOutofBounds {
        /// buf_len parameter
        buf_len: u64,
        /// items_read parameter
        items_read: u64,
    },
    /// Counters are larger than allowed
    #[error("For a ring buffer of length {buf_len}, \
        items_read must be <= {buf_len}, but the actual value is {data_avail}: \
        data_avail = items_written - items_read = {items_written} - {items_read} \
        = {data_avail} (mod 2 * buf_len = {bl2})",
        data_avail = Modulus::<u64>::new_or_panic(buf_len.wrapping_mul(2)).formula([*items_written, *items_read], |[w, r]| {
            w - r
        }),
        bl2 = buf_len.wrapping_mul(2))]
    DataAvailOutOfBounds {
        /// buf_len parameter
        buf_len: u64,
        /// items_written parameter
        items_written: u64,
        /// items_read parameter
        items_read: u64,
    },
}

/// Error produced by [RingBufferScheduler::try_register_read]/[RingBufferScheduler::try_register_write]
#[derive(Debug, thiserror::Error, Clone, Copy, PartialEq, Eq)]
pub enum RingBufferRegisterOpError {
    /// Operation out of bounds given current buffer
    /// [RingBufferScheduler::data_avail]/[RingBufferScheduler::space_avail]
    #[error("Requested operation size ({op_type:?} of len {op_len}) is too large. \
        Given the current ring buffer state, the maximum supported {op_type:?} length is {max_len}. \
        This usually indicates a developer error.")]
    OperationTooLarge {
        /// Operation type
        op_type: OperationType,
        /// Operation length
        op_len: u64,
        /// Maximum allowed operation length
        max_len: u64,
    },
}

impl RingBufferScheduler {
    /// Maximum supported buffer size
    pub const MAX_BUF_LEN: u64 = 1 << (u64::BITS - 1);

    /// Construct a new [Self] from its components
    fn new_raw(buf_len: u64, items_written: u64, items_read: u64) -> Self {
        Self {
            buf_len,
            items_read,
            items_written,
        }
    }

    /// Ensure this ring buffer is in a sound in a sound state
    fn demand_soundness(&self) -> Result<(), RingBufferFromCountersError> {
        let Self {
            buf_len,
            items_written,
            items_read,
        } = *self;

        // There is exactly one valid zero-size buffer representation
        if *self == Self::new_raw(0, 0, 0) {
            return Ok(());
        };

        // Double-check that self.buf_modulus() won't panic
        self.buf_modulus().unwrap();

        // Ensure the buffer length is small enough
        let bm2 = self
            .buf_double_modulus()
            .ok_or(RingBufferNewError::BufferTooLarge(buf_len))?;

        use RingBufferFromCountersError as E;
        bm2.contains(items_written)
            .then_some(())
            .ok_or(E::ItemsWrittenOutOfBounds {
                buf_len,
                items_written,
            })?;
        bm2.contains(items_read)
            .then_some(())
            .ok_or(E::ItemsReadOutofBounds {
                buf_len,
                items_read,
            })?;
        (self.data_avail() <= self.buf_len())
            .then_some(())
            .ok_or(E::DataAvailOutOfBounds {
                buf_len,
                items_written,
                items_read,
            })?;

        Ok(())
    }

    /// Non-panicking variant of [Self::new]
    pub fn try_new(buf_len: u64) -> Result<Self, RingBufferNewError> {
        match Self::try_from_counters(buf_len, 0, 0) {
            Ok(me) => Ok(me),
            Err(RingBufferFromCountersError::RingBufferNewError(e)) => Err(e),
            // Should be impossible
            Err(other_error) => panic!("{other_error:?}"),
        }
    }

    /// Construct a new [Self] from the buffer length, with counters set to zero.
    ///
    /// # Panic
    ///
    /// Panics if buf_len > [Self::MAX_BUF_LEN]
    pub fn new(buf_len: u64) -> Self {
        Self::try_new(buf_len).unwrap()
    }

    /// Construct a ring buffer with specific counter values
    ///
    /// Non-panicking variant of [Self::from_counters]
    pub fn try_from_counters(
        buf_len: u64,
        items_written: u64,
        items_read: u64,
    ) -> Result<Self, RingBufferFromCountersError> {
        let r = Self::new_raw(buf_len, items_written, items_read);
        r.demand_soundness()?;
        Ok(r)
    }

    /// Construct a ring buffer scheduler from the buffer length and the current values of the
    ///
    /// Counters are taken modulo `2 * buf_len` upon creation.
    ///
    /// # Panic
    ///
    /// Panics if [Self::try_from_counters] would throw an error. See
    /// [RingBufferFromCountersError].
    pub fn from_counters(buf_len: u64, items_written: u64, items_read: u64) -> Self {
        Self::try_from_counters(buf_len, items_written, items_read).unwrap()
    }

    /// Create a differential over two ring buffer schedulers
    pub fn diff_old(&self, old: &Self) -> RingBufferSchedulerDiff {
        RingBufferSchedulerDiff::new(old.copy(), self.copy())
    }

    /// Notify the ring buffer about a read having been made
    #[allow(clippy::double_must_use)]
    #[must_use]
    pub fn try_register_read(&self, len: u64) -> Result<Self, RingBufferRegisterOpError> {
        self.try_register_operation_manually(OperationType::Read, len)
    }

    /// Notify the ring buffer about a write having been made.
    ///
    /// Returns an error, if the write is longer than it could have currently supported.
    #[allow(clippy::double_must_use)]
    #[must_use]
    pub fn try_register_write(&self, len: u64) -> Result<Self, RingBufferRegisterOpError> {
        self.try_register_operation_manually(OperationType::Write, len)
    }

    /// Calls [Self::register_read]/[Self::register_write]
    /// based on the operation given
    #[rustfmt::skip]
    #[allow(clippy::double_must_use)]
    #[must_use]
    pub fn try_register_operation_manually(
        &self,
        op: OperationType,
        len: u64,
    ) -> Result<Self, RingBufferRegisterOpError> {
        let max_op_len = self.max_operation_len(op);
        if len > max_op_len {
            return Err(RingBufferRegisterOpError::OperationTooLarge {
                op_type: op,
                op_len: len,
                max_len: max_op_len,
            });
        }

        let m = match self.buf_double_modulus() {
            None => return self.copy().ok(), // Zero-sized
            Some(m) => m,
        };

        self.copy().mutating(|v| {
            v.operation_counter_mut(op).mutate(|ctr| {
                m.formula([ctr, len], |[ctr, len]| {
                    ctr + len
                })
            });
        }).ok()
    }

    /// Notify the ring buffer about a read having been made
    ///
    /// # Panic
    ///
    /// Panics if the read is longer than currently possible according to [Self::data_avail()]
    #[must_use]
    pub fn register_read(&self, len: u64) -> Self {
        self.try_register_read(len).unwrap()
    }

    /// Notify the ring buffer about a write having been made.
    ///
    /// # Panic
    ///
    /// Panics if the read is longer than currently possible according to [Self::space_avail()]
    #[must_use]
    pub fn register_write(&self, len: u64) -> Self {
        self.try_register_write(len).unwrap()
    }

    /// Calls [Self::register_read]/[Self::register_write]
    /// according to the operation given
    ///
    /// # Panics
    ///
    /// If [Self::try_register_operation_manually] would return an error
    #[must_use]
    pub fn register_operation_manually(&self, op: OperationType, len: u64) -> Self {
        self.try_register_operation_manually(op, len).unwrap()
    }

    /// Used to register an operation generated using [Self::schedule_next_write]/[Self::schedule_next_read]/[Self::schedule_reads]/[Self::schedule_next_write],
    /// provided the operation was executed faithfully and for the full length indicated in the
    /// operation
    ///
    /// Slightly easier than calling [Self::try_register_write]/[Self::try_register_read] manually.
    ///
    /// # Panics
    ///
    /// If [Self::try_register_operation] would return an error
    #[must_use]
    pub fn register_operation<Op: RegisterableOperation>(&self, op: &Op) -> Self {
        self.try_register_operation(op).unwrap()
    }

    /// Non-panicking variant of [Self::register_scheduled_operation]
    #[must_use]
    #[allow(clippy::double_must_use)]
    pub fn try_register_operation<Op: RegisterableOperation>(
        &self,
        op: &Op,
    ) -> Result<Self, <Op as RegisterableOperation>::Error> {
        op.register(self.copy())
    }

    /// Number of total items written to the ring buffer (mod 2 * buf_len); this exactly the value passed to
    /// [Self::new]
    pub fn items_read(&self) -> u64 {
        self.items_read
    }

    /// Number of total items read forom the ring buffer (mod 2 * buf_len); this exactly the value passed to
    /// [Self::new]
    pub fn items_written(&self) -> u64 {
        self.items_written
    }

    /// Calls [Self::items_written]/[Self::items_read] according to the
    /// operation given
    pub fn operation_counter(&self, op: OperationType) -> u64 {
        match op {
            OperationType::Write => self.items_written,
            OperationType::Read => self.items_read,
        }
    }

    /// Like [Self::operation_counter], but returns a mutable reference
    fn operation_counter_mut(&mut self, op: OperationType) -> &mut u64 {
        match op {
            OperationType::Write => &mut self.items_written,
            OperationType::Read => &mut self.items_read,
        }
    }

    /// Calls [Self::read_off]/[Self::write_off] according to the
    /// operation given
    pub fn operation_offset(&self, op: OperationType) -> u64 {
        let ctr = self.operation_counter(op);
        match self.is_zero_sized() {
            false => ctr % self.buf_len(),
            true => {
                assert_eq!(ctr, 0); // Purely defensive
                0
            }
        }
    }

    /// Read offset in the ring buffer;
    ///
    /// ```txt
    /// read_off = items_read % buf_len
    /// ```
    pub fn read_off(&self) -> u64 {
        self.operation_offset(OperationType::Read)
    }

    /// Write offset in the ring buffer;
    ///
    /// ```txt
    /// write_off = items_written % buf_len
    /// ```
    pub fn write_off(&self) -> u64 {
        self.operation_offset(OperationType::Write)
    }

    /// Length of the ring buffer; this exactly the value passed to
    /// [Self::new]
    pub fn buf_len(&self) -> u64 {
        self.buf_len
    }

    /// Check whether [Self::buf_len()] == 0
    pub fn is_zero_sized(&self) -> bool {
        self.buf_len() == 0
    }

    /// [Self::buf_len] converted to [Modulus], for internal use
    fn buf_modulus(&self) -> Option<Modulus<u64>> {
        // Won't panic, because we checked in [Self::try_new] that the buffer is small enough
        match self.buf_len() {
            0 => None,
            l => Some(Modulus::new_or_panic(l)),
        }
    }

    /// [Self::buf_modulus()].[double()](Modulus::double).[unwrap()](Result::unwrap); we know this
    /// can not panic because we ensured the buffer is small enough in [Self::try_new()].
    fn buf_double_modulus(&self) -> Option<Modulus<u64>> {
        self.buf_modulus().and_then(|m| m.double())
    }

    /// Calls [Self::data_avail] for reads or [Self::space_avail] for writes for writes
    pub fn max_operation_len(&self, op: OperationType) -> u64 {
        match op {
            OperationType::Read => self.data_avail(),
            OperationType::Write => self.space_avail(),
        }
    }

    /// How many items can be read from the ring buffer
    ///
    /// ```txt
    /// data_avail =
    ///     if items_written == items_read then 0
    ///     if items_written != items_read then write_off - read_off (mod buf_len)
    /// ```
    ///
    /// It would be simpler to calculate data_avail directly from items_read/written
    ///
    /// ```rust,ignore
    /// items_written - items_read
    /// ```
    ///
    /// unfortunately, this method breaks when the underlying u64 value is overflowing.
    #[rustfmt::skip]
    pub fn data_avail(&self) -> u64 {
        self.buf_double_modulus().map(|bm2| {
            bm2.formula([self.items_written(), self.items_read()], |[w, r]| {
                w - r
            })
        }).unwrap_or(0)
    }

    /// How many items can be written to the ring buffer
    ///
    /// ```txt
    /// space_avail = buf_len - data_avail
    ///             = buf_len - (items_written - items_read)
    /// ```
    pub fn space_avail(&self) -> u64 {
        self.buf_len() - self.data_avail()
    }

    /// How full the ring buffer is
    pub fn fill_state(&self) -> BufferFillState {
        use BufferFillState as F;
        match (self.is_empty(), self.is_full()) {
            (true, false) => F::Empty,
            (false, false) => F::Partial,
            (false, true) => F::Full,
            (true, true) => panic!(
                "Contradiction! Buffer can not be both full and empty. This is a developer error."
            ),
        }
    }

    /// Whether the ring buffer is empty
    pub fn is_empty(&self) -> bool {
        self.data_avail() == 0
    }

    /// Whether the ring buffer is full
    pub fn is_full(&self) -> bool {
        self.space_avail() == 0
    }

    /// Whether the ring buffer not empty
    pub fn is_nonempty(&self) -> bool {
        !self.is_empty()
    }

    /// Whether the ring buffer not full
    pub fn is_nonfull(&self) -> bool {
        !self.is_full()
    }

    /// Offset of Block 0 in the buffer
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_0_off(&self) -> u64 {
        0
    }

    /// Offset of Block 1 in the buffer
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_1_off(&self) -> u64 {
        std::cmp::min(self.read_off(), self.write_off())
    }

    /// Offset of Block 2 in the buffer
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_2_off(&self) -> u64 {
        std::cmp::max(self.read_off(), self.write_off())
    }

    /// Length of Block 0
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_0_len(&self) -> u64 {
        self.block_1_off() - self.block_0_off()
    }

    /// Length of Block 1
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_1_len(&self) -> u64 {
        self.block_2_off() - self.block_1_off()
    }

    /// Length of Block 2
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_2_len(&self) -> u64 {
        self.buf_len() - self.block_2_off()
    }

    /// Ring buffer layout
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn layout(&self) -> BufferLayout {
        let ord = std::cmp::Ord::cmp(&self.read_off(), &self.write_off());
        let fill = self.fill_state();

        use std::cmp::Ordering as O;
        use BufferFillState as F;
        match (ord, fill) {
            (O::Less, F::Partial) => BufferLayout::FreeDataFree,
            (O::Greater, F::Partial) => BufferLayout::DataFreeData,
            (O::Equal, F::Empty) => BufferLayout::FreeDataFree,
            (O::Equal, F::Full) => BufferLayout::DataFreeData,
            (ord, fill) => panic!(
                "\
                Contradictory buffer layout. \
                Ordering cmp(read_off_mod = {}, write_off_mod = {}) = {ord:?}, but \
                fill state is {fill:?}. This is a developer error.\
                ",
                self.read_off(),
                self.write_off(),
            ),
        }
    }

    /// Access meta data about Block 0
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_0(&self) -> Block {
        let (typ, no) = match self.layout() {
            BufferLayout::DataFreeData => (BlockType::Data, Bit::One),
            BufferLayout::FreeDataFree => (BlockType::Free, Bit::One),
        };
        Block::new(typ, no, self.block_0_off(), self.block_0_len())
    }

    /// Access meta data about Block 1
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_1(&self) -> Block {
        let (typ, no) = match self.layout() {
            BufferLayout::DataFreeData => (BlockType::Free, Bit::Zero),
            BufferLayout::FreeDataFree => (BlockType::Data, Bit::Zero),
        };
        Block::new(typ, no, self.block_1_off(), self.block_1_len())
    }

    /// Access meta data about Block 2
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn block_2(&self) -> Block {
        let (typ, no) = match self.layout() {
            BufferLayout::DataFreeData => (BlockType::Data, Bit::Zero),
            BufferLayout::FreeDataFree => (BlockType::Free, Bit::Zero),
        };
        Block::new(typ, no, self.block_2_off(), self.block_2_len())
    }

    /// Access meta data about all Blocks in the ring buffer
    ///
    /// See [Self] for more information on the ring buffer memory layout
    pub fn blocks(&self) -> [Block; 3] {
        [self.block_0(), self.block_1(), self.block_2()]
    }

    /// Which contiguous memory block to use for the next operation
    ///
    /// See [Self] for more information on the ring buffer memory layout.
    ///
    /// Calls [Self::next_read_block]/[Self::next_write_block] as specified by the operation.
    ///
    /// Note that the resulting block can be zero-sized if the ring buffer is empty/full.
    pub fn next_operation_block(&self, op: OperationType) -> Block {
        use BufferLayout as L;
        use OperationType as O;

        match (self.layout(), op) {
            (L::DataFreeData, O::Read) => self.block_2(),
            (L::FreeDataFree, O::Read) => self.block_1(),
            (L::DataFreeData, O::Write) => self.block_1(),
            (L::FreeDataFree, O::Write) => self.block_2(),
        }
    }

    /// Which contiguous memory block to use for the next read operation
    ///
    /// See [Self] for more information on the ring buffer memory layout
    ///
    /// Note that the resulting block can be zero-sized if the ring buffer is empty.
    pub fn next_read_block(&self) -> Block {
        self.next_operation_block(OperationType::Read)
    }

    /// Which contiguous memory block to use for the next write operation
    ///
    /// See [Self] for more information on the ring buffer memory layout
    ///
    /// Note that the resulting block can be zero-sized if the ring buffer is full.
    pub fn next_write_block(&self) -> Block {
        self.next_operation_block(OperationType::Write)
    }

    /// Schedule an operation on the ring buffer.
    ///
    /// Calls [Self::schedule_next_read]/[Self::schedule_next_write] as per
    /// the operation given.
    pub fn schedule_next_contigous_operation<Size: TruncateIntoU64USize>(
        &self,
        op: OperationType,
        max_len: Size,
    ) -> Option<ScheduledOperation> {
        let max_len = max_len.truncate_to_u64usize().u64();
        let block = self.next_operation_block(op);
        let len = std::cmp::min(block.len, max_len);
        let op = ScheduledOperation::new(op, block.off, U64USize::new_or_panic(len));
        (len > 0).then_some(op)
    }

    /// Schedule a contiguous read operation on the ring buffer.
    ///
    /// Will return [None] if the ring buffer is empty.
    ///
    /// The result takes the destination length into account and can be immediately used
    /// for reads from the ring buffer into a contiguous slice of memory.
    ///
    /// Passing arbitrarily large destination sizes is valid; passing [usize]::MAX as the
    /// destination length is explicitly supported and will just yield the maximum possible
    /// contiguous read supported by the ring buffer.
    ///
    /// Note that this function will never schedule operations of a length that can not be represented
    /// in both a u64 and a usize. For 64 bit systems, this is not a limitation in practice. For 32
    /// bit systems it means that scheduled operations are restricted to around 4GB of data
    /// transferred in one go.
    pub fn schedule_next_read<Size: TruncateIntoU64USize>(
        &self,
        dst_len: Size,
    ) -> Option<ScheduledOperation> {
        self.schedule_next_contigous_operation(OperationType::Read, dst_len)
    }

    /// Schedule a contiguous write operation on the ring buffer.
    ///
    /// Will return [None] if the ring buffer is full.
    ///
    /// The result takes the destination length into account and can be immediately used
    /// for writes from the ring buffer into a contiguous slice of memory.
    ///
    /// Passing arbitrarily large destination sizes is valid; passing [usize]::MAX or [u64]::MAX as the
    /// destination length is explicitly supported and will just yield the maximum possible
    /// contiguous read supported by the ring buffer.
    ///
    /// Note that this function will never schedule operations of a length that can not be represented
    /// in both a u64 and a usize. For 64 bit systems, this is not a limitation in practice. For 32
    /// bit systems it means that scheduled operations are restricted to around 4GB of data
    /// transferred in one go.
    pub fn schedule_next_write<Size: TruncateIntoU64USize>(
        &self,
        src_len: Size,
    ) -> Option<ScheduledOperation> {
        self.schedule_next_contigous_operation(OperationType::Write, src_len)
    }

    /// Schedule multiple contiguous operations
    ///
    /// Note that this function will never schedule operations of a length that can not be represented
    /// in both a u64 and a usize. For 64 bit systems, this is not a limitation in practice. For 32
    /// bit systems it means that the total size of scheduled operations is restricted to around 4GB of data.
    pub fn schedule_contigous_operations<Size: TruncateIntoU64USize>(
        &self,
        op_type: OperationType,
        max_len: Size,
    ) -> ScheduledOperations {
        let max_len = max_len.truncate_to_u64usize();
        let op1 = self.schedule_next_contigous_operation(op_type, max_len);
        let op2 = op1.and_then(|op1| {
            self.register_operation(&op1)
                .schedule_next_contigous_operation(op_type, max_len.u64() - op1.len.u64())
        });

        let cont = [op1, op2].iter().filter_map(|maybe_op| *maybe_op).collect();

        // Wont panic, since we truncated max_len
        ScheduledOperations::new_or_panic(cont)
    }

    /// Like [Self::schedule_next_read()], but returns between zero and two scheduled operations,
    /// potentially draining the entire ring buffer.
    pub fn schedule_reads<Size: TruncateIntoU64USize>(&self, dst_len: Size) -> ScheduledOperations {
        self.schedule_contigous_operations(OperationType::Read, dst_len)
    }

    /// Like [Self::schedule_next_write()], but returns between zero and two scheduled operations,
    /// potentially filling the entire ring buffer.
    pub fn schedule_writes<Size: TruncateIntoU64USize>(
        &self,
        src_len: Size,
    ) -> ScheduledOperations {
        self.schedule_contigous_operations(OperationType::Write, src_len)
    }
}

impl std::fmt::Debug for RingBufferScheduler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RingBufferScheduler")
            .field("buf_len()", &self.buf_len())
            .field("read_off()", &self.items_read())
            .field("read_off_mod()", &self.read_off())
            .field("write_off()", &self.items_written())
            .field("write_off_mod()", &self.write_off())
            .field("data_avail()", &self.data_avail())
            .field("space_avail()", &self.space_avail())
            .field("fill_state()", &self.fill_state())
            .field("is_empty()", &self.is_empty())
            .field("is_full()", &self.is_full())
            .field("block_1()", &self.block_0())
            .field("block_2()", &self.block_1())
            .field("block_3()", &self.block_2())
            .field("layout()", &self.layout())
            .field("next_read_block()", &self.next_read_block())
            .field("next_write_block()", &self.next_write_block())
            .finish()
    }
}
