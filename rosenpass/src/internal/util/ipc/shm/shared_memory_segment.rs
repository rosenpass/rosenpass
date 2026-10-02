//! Accessing data in a shared memory segment

use std::{
    borrow::Borrow,
    os::fd::{AsFd, OwnedFd},
};

use crate::internal::util::{
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
    /// Create a new shared memory segment builder.
    ///
    /// Note that this always sets [MapFdConfig::set_shared()], but you can overwrite this
    /// behavior by assigning to the public [Self::map_fd_cfg] field directly. (mmap()
    /// rejects private mappings of memfd_secret(2) file descriptors; see
    /// [MapFdConfig::shared].)
    ///
    /// The file descriptor is created with [SecretMemfdConfig::used_in_shared_memory()]; on
    /// systems where memfd_secret(2) is not protected against resizing, this makes
    /// [SecretMemfdConfig::validate_config()] reject configurations that would use
    /// memfd_secret(2) for shared memory, instead of proceeding insecurely.
    pub fn new(len: usize) -> anyhow::Result<Self> {
        let secret_memfd_cfg = SecretMemfdConfig::new().used_in_shared_memory();
        let map_fd_cfg = secret_memfd_cfg
            .map_fd_config()?
            .set_shared()
            .resize_on_mmap(usize_to_u64(len));
        Ok(Self {
            secret_memfd_cfg,
            map_fd_cfg,
        })
    }

    /// Create a shared memory segment using the configuration stored here
    ///
    /// The freshly created segment is zero-filled (fresh memfd pages are zero-filled by the
    /// kernel).
    pub fn create_segment(&self) -> anyhow::Result<(OwnedFd, SharedMemorySegment)> {
        let fd = self.secret_memfd_cfg.create()?;

        let cfg = self.map_fd_cfg;
        let fd = fd.with_config(cfg);
        let seg = fd.mmap()?;
        // SAFETY: fresh file descriptor created just above; this is the only mapping of
        // it in this process. The volatile-access soundness argument of
        // [SharedMemorySegment] applies.
        let seg = unsafe { SharedMemorySegment::from_mapped_segment(seg) };

        Ok((fd.into_fd(), seg))
    }
}

/// Safe creation of and access to shared memory segments
///
/// # Safety
///
/// Any means to create a [Self] must guarantee that further calls to [Self::volatile_write] and
/// [Self::volatile_read] are also safe. Concretely, the caller must guarantee:
///
/// - The backing memory object is of at least the given size. (This is
///   checked at runtime by the checked size policy; a violation is an error, not undefined
///   behavior.)
/// - The mapping stays valid for the lifetime of the segment: the file descriptor is sealed
///   against resizing (requested by default; see the "In practice" section below) and no
///   other code may munmap(2) or mprotect(2) the region.
/// - No Rust references (`&[u8]`/`&mut [u8]`) into the segment's memory are ever created;
///   with an untrusted writer on the other end, creating such references is undefined
///   behavior independent of the volatile-access discussion below.
/// - The caller accepts the "undefined behavior in theory, tearing in practice" position
///   for untrusted peers documented below.
///
/// The API of this struct is specifically designed so that creating aliasing volatile
/// *access* to the same shared memory segment is impossible without unsafe code: safe code
/// cannot create a second [SharedMemorySegment] of the same segment (all constructors from
/// existing objects are unsafe), and a plain [MappedSegment] exposes only raw pointers, so
/// reading or writing a second mapping requires unsafe code as well.
///
/// Note that a second *mapping* can still come into existence without
/// unsafe code — via the safe
/// [MappableFd](crate::internal::util::secret_memory::mmap::MappableFd) API on the returned
/// file descriptor — but such a mapping cannot be read or written through safe code.
/// This guarantee covers only programs that never call fork(2): a forked child inherits
/// the mapping together with the [SharedMemorySegment] value, so the child's safe methods
/// operate on the same pages; fork(2) is only reachable through unsafe code.
///
/// We recognize that the sole purpose of shared memory segments is that multiple mappings of
/// them are created; there probably just is no way to do so using safe Rust.
///
/// The reason for this is that, per the Rust documentation, any *data race* — concurrent,
/// unsynchronized, conflicting accesses where at least one access is a write and at least
/// one is non-atomic — leads to undefined behavior; volatile accesses are non-atomic
/// accesses in this sense, even when the racing write is caused solely by an adversarial
/// application on the other end of a shared memory communication channel.
///
/// For this reason, we force users to use unsafe code to create shared memory mappings from an
/// existing file descriptor, as this could potentially lead to adversarial data races (and thus to
/// undefined behavior).
///
/// [SharedMemorySegment] is [Send] but not [Sync]: safe code also cannot share one segment
/// between threads.
///
/// In practice, we believe concurrent memory access using volatile operations is going to
/// lead to nothing worse than garbled data being transferred. The user should treat any data
/// received through a shared-memory ring buffer as untrusted and validate this data anyway, so
/// garbled data should be caught.
///
/// This means that [Self::from_fd()] is unsafe in theory, but most likely safe in practice.
///
/// ## Concurrent, untrusted shared memory is technically undefined behavior
///
/// It's even worse than having to use unsafe: technically speaking, it may be impossible to
/// use shared memory soundly in Rust unless all parties with access to the segment are
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
/// and the fact that we use mmap(2) for allocation do not mitigate this issue; from the
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
/// We take mmap(2) regions to be allocations in this sense — they are addressable from Rust
/// and pointer arithmetic within them is possible. The [std::ptr] documentation does not
/// explicitly list OS-created mappings, so this is an interpretation, albeit the standard one.
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
/// that the line between processes and threads is drawn in the sand. For Linux, read the man page
/// of clone(2):
///
/// > By contrast with fork(2), these [clone, __clone2, clone3] system calls provide more precise control over what pieces of execution
/// > context are shared between the calling process and the child process.  For example, using  these  system
/// > calls,  the caller can control whether or not the two processes share the virtual address space, the
/// > table of file descriptors, and the table of signal handlers.  These system calls also allow the new  child
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
/// According to the man page, "the term 'thread' is used  to refer to the processes within a thread group."
///
/// The Rust (transitively, from the C++11/C++20 atomics) specification tells us that there must be
/// no data races between threads, whether the accesses involved are volatile or not. The Linux man
/// pages tell us that "thread" is just a special type of "process".
///
/// **The most robust interpretation of these specifications is that shared memory must not be used for
/// communication with an untrusted party across thread or process boundaries, or else the other
/// process/thread can cause undefined behavior in our process.**
///
/// ## In practice
///
/// Realistically, using volatile reads/writes on valid, mapped memory might cause garbled values in
/// case of a data race, but it should not crash the program or do anything worse than create
/// garbled values.
///
/// This analysis is premised on the memory staying valid and mapped. That premise is enforced by
/// the resize protection in
/// [MappableFd::mmap()](crate::internal::util::secret_memory::mmap::MappableFd::mmap) (see also
/// [SecretMemfdConfig::validate_config()]): the file descriptor is sealed with
/// F_SEAL_SHRINK|F_SEAL_GROW (or, for memfd_secret(2), protected by the kernel itself), so an
/// adversarial peer cannot truncate it — which would otherwise turn accesses into
/// SIGBUS/SIGSEGV, crashing the program (a denial of service, though not memory-unsafe). With
/// [MapFdConfig::disable_resizing_protection()], that crash risk is accepted instead.
///
/// Mind that we do not mind garbled values here; we are implementing a shared memory communication
/// interface, so our application must always assume that the data it receives may be garbled. It
/// has to be validated. We just don't want the other application to be able to do anything worse
/// than garble the data it is sending (or receiving), so let's estimate what can *realistically*
/// happen here if the other application maliciously causes a race.
///
/// The worst any of the assembly sequences below should do is cause tearing in case of a data
/// race.
///
/// This leads me to the conclusion that what we are dealing with here is not an
/// implementation that is faulty/insecure, instead it is a definition gap in the compiler
/// semantics for volatile memory access for use in security-critical applications.
///
/// Godbolt link: <https://rust.godbolt.org/z/GGjsGsc33> (x86_64 listing only; the other
/// targets were compiled from the same source with the same flags)
/// Compiler: `rustc 1.90.0`; all four listings were regenerated and verified unchanged with
/// `rustc 1.96.0` (2026-09-22)
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
/// (The `#[unsafe(no_mangle)]` attribute syntax is accepted in all editions since
/// Rust 1.82 and mandatory only in edition 2024; this crate uses edition 2021.)
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
/// armv7 (`--target=armv7-unknown-linux-gnueabihf -O`):
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
/// riscv64 (`--target=riscv64gc-unknown-linux-gnu -O`):
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
    ///
    /// The freshly created segment is zero-filled (fresh memfd pages are zero-filled by the
    /// kernel).
    pub fn create(len: usize) -> anyhow::Result<(OwnedFd, Self)> {
        SharedMemorySegmentBuilder::new(len)?.create_segment()
    }

    /// Create a shared memory segment from a file descriptor
    ///
    /// Uses the default [MapFdConfig] (shared mapping, checked size, resize protection
    /// requested); see [Self::from_fd_with_config()] for the failure modes.
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
    /// Unless [MapFdConfig::disable_resizing_protection()] is set in `cfg`, this fails —
    /// rather than mapping insecurely — for file descriptors that cannot be sealed against
    /// resizing (e.g. memfds created without MFD_ALLOW_SEALING, or read-only re-opens via
    /// /proc/self/fd).
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

    /// Whether `self.len() == 0`
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read data from the shared memory segment
    ///
    /// # Panics
    ///
    /// Panics if the range `off .. off + dst.len()` is not fully contained
    /// in the segment (including the case where `off + dst.len()` overflows).
    pub fn volatile_read(&self, dst: &mut [u8], off: usize) {
        // The end computation must not wrap: the workspace does not enable
        // release-mode overflow checks, so plain addition could wrap around
        // and defeat the bounds check below, turning this safe function into
        // an out-of-bounds volatile access
        let end = off
            .checked_add(dst.len())
            .expect("volatile_read: off + dst.len() overflow");
        assert!(end <= self.len());

        // SAFETY: the range off..end was bounds-checked against the segment length just
        // above; mapping validity and the aliasing/access contract are guaranteed by the
        // creator of Self per its # Safety section
        unsafe { self.ptr().add(off).read_mem_volatile(dst) }
    }

    /// Write data to the shared memory segment
    ///
    /// # Panics
    ///
    /// Panics if the range `off .. off + src.len()` is not fully contained
    /// in the segment (including the case where `off + src.len()` overflows).
    pub fn volatile_write(&self, off: usize, src: &[u8]) {
        // See volatile_read: the end computation must not wrap
        let end = off
            .checked_add(src.len())
            .expect("volatile_write: off + src.len() overflow");
        assert!(end <= self.len());

        // SAFETY: the range off..end was bounds-checked against the segment length just
        // above; mapping validity and the aliasing/access contract are guaranteed by the
        // creator of Self per its # Safety section
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
    crate::internal::util::mem::cpy_min(test_string, &mut after_write);

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

/// Enforce overflow checking in volatile_write/volatile_read
#[test]
fn test_volatile_access_offset_overflow_panics() -> anyhow::Result<()> {
    let (_fd, seg) = SharedMemorySegment::create(1024)?;

    // `off + 8` wraps past usize::MAX; the bounds check must still catch it
    let off = usize::MAX - 4;

    let mut dst = [0u8; 8];
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        seg.volatile_read(&mut dst, off)
    }));
    assert!(
        res.is_err(),
        "volatile_read with overflowing off + len must panic"
    );
    // The panic must have happened before any memory was accessed
    assert_eq!(dst, [0u8; 8]);

    let src = [0u8; 8];
    let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        seg.volatile_write(off, &src)
    }));
    assert!(
        res.is_err(),
        "volatile_write with overflowing off + len must panic"
    );

    Ok(())
}
