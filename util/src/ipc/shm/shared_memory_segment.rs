//! Accessing data in a shared memory segment

use std::{
    borrow::Borrow,
    os::fd::{AsFd, OwnedFd},
};

use crate::{
    int::u64uint::usize_to_u64,
    ptr::{ReadMemVolatile, WriteMemVolatile},
    result::OkExt,
    secret_memory::{
        fd::SecretMemfdConfig,
        mmap::{MMapError, MapFdConfig, MappedSegment},
    },
};

/// Safe creation of shared memory segments
///
/// This is a slightly more convenient API than using [MapFdConfig] directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedMemorySegmentBuilder {
    /// Configuration for allocating memory file descriptors and their secrecy level
    pub secret_memfd_cfg: SecretMemfdConfig,
    /// Configuration for mapping file descriptors into memory
    pub map_fd_cfg: MapFdConfig,
}

impl SharedMemorySegmentBuilder {
    /// Create a new secret memory segment builder.
    ///
    /// Note that this always sets [MapFdConfig::set_shared()], but you can overwrite this behavior
    /// by un-setting the flag again.
    ///
    /// # Safety & panic
    ///
    /// This function can panic when [u64] is unable to represent the given size
    /// value. This might be the case in future computers impressing me with their excessive size.
    pub const fn new(len: usize) -> Self {
        let secret_memfd_cfg = SecretMemfdConfig::new();
        let map_fd_cfg = MapFdConfig::new()
            .set_shared()
            .resize_on_mmap(usize_to_u64(len));
        Self {
            secret_memfd_cfg,
            map_fd_cfg,
        }
    }

    /// Create a secret memory segment using the configuration stored here
    pub fn create_segment(&self) -> anyhow::Result<(OwnedFd, SharedMemorySegment)> {
        let fd = self.secret_memfd_cfg.create()?;
        let seg = self.map_fd_cfg.mappable_fd(&fd).mmap()?;
        let seg = unsafe { SharedMemorySegment::from_mapped_segment(seg) };

        Ok((fd, seg))
    }
}

/// Safe creation of and access to shared memory segments
///
/// # Safety
///
/// Any means to create a [Self] must guarantee, that further calls to [Self::volatile_write] and
/// [Self::volatile_read] are also safe.
///
/// The API of this struct is specifically designed so creating multiple memory mappings of the same
/// shared memory segment is impossible without unsafe code.
///
/// We recognize that the sole purpose of shared memory segments is that multiple mappings of them
/// are created, there just is no way to do so using safe rust.
///
/// The reason for this is – that by the Rust documentation – any concurrent memory access leads to
/// undefined behavior, even volatile accesses caused solely by an adversarial application on the
/// other end of a shared memory communication channel.
///
/// For this reason, we force users to use unsafe code to create shared memory mappings from an
/// existing file descriptor, as this could potentially lead to adversarial data races (and thus to
/// undefined behavior).
///
/// In practice, we believe using concurrent memory access using volatile operations is going to
/// lead to nothing worse than garbled data being transferred. The user should treat any data
/// received through a shared-memory ring buffer as untrusted and validate this data any way, so
/// garbled data should be caught.
///
/// This means that [Self::from_fd()] is unsafe in theory, but most likely safe in practice.
///
/// ## Concurrent, untrusted shared memory is technically undefined behavior
///
/// Its even worse than having to use unsafe: technically speaking, it may be impossible to
/// use shared memory soundly in rust unless all parties with access to the segment are
/// *trusted*. If these parties are not trusted (or buggy) they can always cause undefined
/// behavior:
///
/// From the [std::sync::atomic] documentation:
///
/// > **The most important aspect of this model is that data races are undefined behavior.** A data race
/// > is defined as conflicting non-synchronized accesses where at least one of the accesses is non-atomic.
/// > Here, accesses are conflicting if they affect overlapping regions of memory and at least one of them
/// > is a write. (A compare_exchange or compare_exchange_weak that does not succeed is not considered a
/// > write.) They are non-synchronized if neither of them happens-before the other, according to the
/// > happens-before order of the memory model.
///
/// The fact that this API uses volatile [reads](Self::volatile_read) and [writes](Self::volatile_write),
/// and the the fact that we use mmap(2) for allocation does not mitigate this issue; from the
/// documentation of [std::ptr::write_volatile()]:
///
/// > When a volatile operation is used for memory inside an allocation, it behaves exactly like write,
/// > except for the additional guarantee that it won’t be elided or reordered (see above). This implies
/// > that the operation will actually access memory and not e.g. be lowered to a register access. Other
/// > than that, all the usual rules for memory accesses apply (including provenance). In particular, just
/// > like in C, whether an operation is volatile has no bearing whatsoever on questions involving concurrent
/// > access from multiple threads. Volatile accesses behave exactly like non-atomic accesses in that regard.
///
/// An allocation is defined as follows (taken from [std::ptr]):
///
/// > An allocation is a subset of program memory which is addressable from Rust, and within which pointer
/// > arithmetic is possible. Examples of allocations include heap allocations, stack-allocated variables,
/// > statics, and consts. The safety preconditions of some Rust operations - such as offset and field
/// > projections (expr.field) - are defined in terms of the allocations on which they operate.
///
/// This definition clearly applies to mmap(2) allocated regions.
///
/// What might mitigate this issue is mapping the region just once per process:
///
/// > In particular, just
/// > like in C, whether an operation is volatile has no bearing whatsoever on questions involving concurrent
/// > access from **multiple threads**.
///
/// We could argue that a process is not a thread, and thus concurrent access from two processes is
/// fine, but concurrent access from two threads is not (unless guarded by an atomic value or a
/// mutex or some primitive actually designed for synchronization).
///
/// There is no wording in the spec explicitly allowing raceful, concurrent access from multiple processes.
///
/// The problem with basing our safety-argument on the claim that "processes are not threads" is
/// that the line between processes and threads is drawn in the sand. For linux, read the man page
/// of clone(2):
///
/// > By contrast with fork(2), these [clone, __clone2, clone3] system calls provide more precise control over what pieces of execution
/// > context are shared between the calling process and the child process.  For example, using  these  system
/// > calls,  the caller can control whether or not the two processes share the virtual address space, the ta‐
/// > ble of file descriptors, and the table of signal handlers.  These system calls also allow the new  child
/// > process to be placed in separate namespaces(7).
/// >
/// > […]
/// >
/// > ## CLONE_THREAD (since Linux 2.4.0)
/// >
/// > If  CLONE_THREAD is set, the child is placed in the same thread group as the calling process.  To
/// > make the remainder of the discussion of CLONE_THREAD more readable, the term "thread" is used  to
/// > refer to the processes within a thread group.
///
/// According to the man page, "the term 'thread' is used  to refer to the processes within a thread group.".
///
/// The Rust (transitively, from the C++11 Atomic) specification tells us that there must be no
/// concurrent memory access between threads whether this access is volatile or not. The linux man
/// pages tell us that "thread" is just a special type of "process".
///
/// **The most robust interpretation of these specifications is that shared memory must not be used for
/// communication with an untrusted party across thread or process boundaries, or else the other
/// process/thread can cause undefined behavior in our process.**
///
/// ## In practice
///
/// Realistically, using volatile reads/writes on valid, mapped memory might cause garbled values in
/// case of a data race, but it should crash the program or do anything worse than create garbled
/// values.
///
/// Mind that we do not mind garbled values here; we are implementing a shared memory communication
/// interface, so our application must always assume, that the data it receives may be garbled. It
/// has to be validated. We just don't want the other application to be able to do anything worse
/// that garble the data it is sending (or receiving), so lets estimate what can *realistically*
/// happen here if the other application maliciously causes a race.
///
/// The worst any of the assembly sequences below should do is cause tearing in case of a data
/// race.
///
/// This leads me to the conclusion that what what we are dealing here with is not an
/// implementation that is faulty/insecure, instead it is a definition-gap in the compiler
/// semantics for volatile memory access for use in security-critical applications.
///
/// Godbolt link: <https://rust.godbolt.org/z/GGjsGsc33>
/// Compiler: `rustc 1.90.0`
///
/// Rust code:
///
/// ```rust
/// #[unsafe(no_mangle)]
/// pub fn read_volatile(num: &[u128]) -> u128 {
///     let ptr = num.as_ptr();
///     unsafe { ptr.read_volatile() }
/// }
///
/// #[unsafe(no_mangle)]
/// pub fn write_volatile(num: &mut [u128]) {
///     let ptr = num.as_mut_ptr();
///     unsafe { ptr.write_volatile(42u128) };
/// }
/// ```
///
/// x86_64 (`--target=x86_64-unknown-linux-gnu -O`):
///
/// ```asm
/// read_volatile:
///         mov     rax, qword ptr [rdi]
///         mov     rdx, qword ptr [rdi + 8]
///         ret
///
/// write_volatile:
///         mov     qword ptr [rdi + 8], 0
///         mov     qword ptr [rdi], 42
///         ret
/// ```
///
/// arm64 (`--target=aarch64-unknown-linux-gnu -O`):
///
/// ```asm
/// read_volatile:
///         ldp     x0, x1, [x0]
///         ret
///
/// write_volatile:
///         mov     w8, #42
///         stp     x8, xzr, [x0]
///         ret
/// ```
///
/// armv7 (`--target=armv7-unknown-linux-gnueabihf -O`)
///
/// ```asm
/// read_volatile:
///         push    {r4, r5, r11, lr}
///         ldrd    r2, r3, [r1]
///         ldrd    r4, r5, [r1, #8]
///         stm     r0, {r2, r3, r4, r5}
///         pop     {r4, r5, r11, pc}
///
/// write_volatile:
///         push    {r4, r5, r11, lr}
///         mov     r2, #0
///         mov     r4, #42
///         mov     r3, r2
///         mov     r5, r2
///         strd    r2, r3, [r0, #8]
///         strd    r4, r5, [r0]
///         pop     {r4, r5, r11, pc}
/// ```
///
/// risc64 (`--target=riscv64gc-unknown-linux-gnu`):
///
/// ```asm
/// read_volatile:
///         ld      a1, 8(a0)
///         ld      a0, 0(a0)
///         ret
///
/// write_volatile:
///         sd      zero, 8(a0)
///         li      a1, 42
///         sd      a1, 0(a0)
///         ret
/// ```
///
#[derive(Debug)]
pub struct SharedMemorySegment {
    /// The underlying mapped segment
    inner: MappedSegment,
}

impl SharedMemorySegment {
    /// Create a new shared memory segment.
    pub fn create(len: usize) -> anyhow::Result<(OwnedFd, Self)> {
        SharedMemorySegmentBuilder::new(len).create_segment()
    }

    /// Create a shared memory segment from a file descriptor
    ///
    /// # Safety
    ///
    /// See the comments in [Self].
    pub unsafe fn from_fd<Fd: AsFd>(fd: Fd, size: usize) -> Result<Self, MMapError> {
        let cfg = MapFdConfig::new()
            .set_shared()
            .expected_size(usize_to_u64(size));
        unsafe { Self::from_fd_with_config(fd, cfg) }
    }

    /// Create a shared memory segment from a file descriptor
    ///
    /// # Safety
    ///
    /// See the comments in [Self].
    pub unsafe fn from_fd_with_config<Fd: AsFd>(
        fd: Fd,
        cfg: MapFdConfig,
    ) -> Result<Self, MMapError> {
        let segment = cfg.mappable_fd(&fd).mmap()?;
        unsafe { Self::from_mapped_segment(segment).ok() }
    }

    /// Create a shared memory segment from an existing mapped segment
    ///
    /// # Safety
    ///
    /// See the comments in [Self].
    pub unsafe fn from_mapped_segment(inner: MappedSegment) -> Self {
        Self { inner }
    }

    /// The underlying mapped segment
    pub fn mapped_segment(&self) -> &MappedSegment {
        self.inner.borrow()
    }

    /// A pointer to the underlying mapped segment
    pub fn ptr(&self) -> *mut u8 {
        self.mapped_segment().ptr()
    }

    /// The length of the underlying mapped segment
    pub fn len(&self) -> usize {
        self.mapped_segment().len()
    }

    /// Whether `self.`[len()](Self::len)` == 0`
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read data from the ring buffer
    ///
    /// # Safety
    ///
    /// See comments in [Self].
    pub fn volatile_read(&self, dst: &mut [u8], off: usize) {
        let end = off + dst.len();
        assert!(end <= self.len());

        unsafe { self.ptr().add(off).read_mem_volatile(dst) }
    }

    /// Read data from the ring buffer
    ///
    /// # Safety
    ///
    /// See comments in [Self].
    pub fn volatile_write(&self, off: usize, src: &[u8]) {
        let end = off + src.len();
        assert!(end <= self.len());

        unsafe { self.ptr().add(off).write_mem_volatile(src) }
    }
}

impl From<SharedMemorySegment> for MappedSegment {
    fn from(val: SharedMemorySegment) -> Self {
        val.inner
    }
}

impl Borrow<MappedSegment> for SharedMemorySegment {
    fn borrow(&self) -> &MappedSegment {
        self.mapped_segment()
    }
}

#[test]
fn test_shared_memory_segment() -> anyhow::Result<()> {
    let underscore = [b'_'; 38];
    let zero = [0u8; 38];
    let test_string = b"Hello World";

    let mut after_write = zero.to_owned();
    crate::mem::cpy_min(test_string, &mut after_write);

    let (fd, reg1) = SharedMemorySegment::create(1024)?;
    let reg2 = unsafe { SharedMemorySegment::from_fd(fd, 1024) }?;

    let mut buf = underscore.to_owned();
    reg1.volatile_read(&mut buf, 0);
    assert_eq!(&buf, &zero);

    let mut buf = underscore.to_owned();
    reg2.volatile_read(&mut buf, 0);
    assert_eq!(&buf, &zero);

    reg1.volatile_write(0, test_string);

    let mut buf = underscore.to_owned();
    reg1.volatile_read(&mut buf, 0);
    assert_eq!(&buf, &after_write);

    let mut buf = underscore.to_owned();
    reg2.volatile_read(&mut buf, 0);
    assert_eq!(&buf, &after_write);

    Ok(())
}
