//! This entire module is dedicated to the implementation of
//! [super::MappableFd::mmap()]; mod.rs contains the interface,
//! while this file handles all the implementation details of
//! memory allocation.
//!
use std::{
    os::fd::{AsFd, BorrowedFd},
    ptr::null_mut,
};

use rustix::{fs::SealFlags, io::Errno};

use crate::internal::util::{
    functional::SideffectExt,
    int::u64uint::MAX_U64_IN_USIZE,
    mem::{CopyExt, DiscardResultExt},
    result::OkExt,
    secret_memory::fd::memfd_secret_protects_against_resizing,
    secret_memory::mmap::{
        MMapError, MMapInvalidConfigError, MMapSizePolicy, MapFdConfig, MappableFd, MappedSegment,
        MemfdCreateSealError,
    },
};

/// (F_SEAL_SHRINK | F_SEAL_GROW): The required seal set;
/// needed to prevent adversarial users in shared memory from
/// triggering SIGSEGV/SIGBUS (invalid memory access) by truncating
/// the shared file descriptor
const SRESIZE: SealFlags = SealFlags::SHRINK.union(SealFlags::GROW);

/// (F_SEAL_SEAL): Never installed; used only to detect file
/// descriptors that are already sealed against adding further seals
///
/// F_SEAL_SEAL is deliberately NOT installed: third parties holding
/// the same file descriptor can only ever ADD seals, never remove
/// ours, so our resize protection cannot be weakened; leaving the
/// seal set open permits installing further seals later (e.g.
/// F_SEAL_FUTURE_WRITE)
const SSEAL: SealFlags = SealFlags::SEAL;

/// Lifecycle of the mapping being assembled by [AllocationCode]
#[derive(Debug)]
enum SegmentLifecycle {
    /// No mapping prepared at all
    None,
    /// The anonymous guard-page has been allocated; its middle still
    /// contains PROT_NONE pages
    GuardPage(MappedSegment),
    /// Finished allocation; guard pages have been allocated AND data pages too
    DataPage(MappedSegment),
}

impl SegmentLifecycle {
    /// Consume `self`, returning the owned [MappedSegment] if there is one
    /// and [None] if no mapping is owned
    pub fn into_segment(self) -> Option<MappedSegment> {
        match self {
            Self::None => None,
            Self::GuardPage(m) => Some(m),
            Self::DataPage(m) => Some(m),
        }
    }

    /// Mutable reference to the owned segment, whichever variant currently
    /// holds it; [None] if no mapping is owned
    pub fn segment_mut(&mut self) -> Option<&mut MappedSegment> {
        match self {
            Self::None => None,
            Self::GuardPage(m) => Some(m),
            Self::DataPage(m) => Some(m),
        }
    }

    /// Whether the file-descriptor data page has been mapped (the state is
    /// [Self::DataPage])
    pub fn is_data_page(&self) -> bool {
        self.data_page().is_some()
    }

    /// Mutable reference to the segment, only if the data page has been
    /// mapped; [None] otherwise
    pub fn data_page_mut(&mut self) -> Option<&mut MappedSegment> {
        match self {
            Self::DataPage(m) => Some(m),
            _ => None,
        }
    }

    /// Reference to the segment, only if the data page has been mapped;
    /// [None] otherwise
    pub fn data_page(&self) -> Option<&MappedSegment> {
        match self {
            Self::DataPage(m) => Some(m),
            _ => None,
        }
    }

    /// Take ownership of the segment if the data page has been mapped,
    /// leaving [Self::None] behind; returns [None] and leaves the state
    /// unchanged otherwise
    pub fn take_data_page(&mut self) -> Option<MappedSegment> {
        self.data_page()?; // Check it's really a data page
        self.take_segment()
    }

    /// Take ownership of the segment whatever kind it is, leaving
    /// [Self::None] behind; returns [None] if no mapping is owned.
    pub fn take_segment(&mut self) -> Option<MappedSegment> {
        let mut tmp = Self::None;
        std::mem::swap(self, &mut tmp);
        tmp.into_segment()
    }

    /// Store `guard_page` as the owned segment, replacing (and dropping) any
    /// segment already stored, and return a mutable reference to it.
    pub fn insert_guard_page(&mut self, guard_page: MappedSegment) -> &mut MappedSegment {
        *self = Self::GuardPage(guard_page);
        self.segment_mut().unwrap()
    }

    /// Store `data_page` as the owned segment, replacing (and dropping) any
    /// segment already stored, and return a mutable reference to it.
    pub fn insert_data_page(&mut self, data_page: MappedSegment) -> &mut MappedSegment {
        *self = Self::DataPage(data_page);
        self.segment_mut().unwrap()
    }
}

/// This really just implements [super::MappableFd::mmap()];
/// because the implementation is quite complex, we move it here
/// into this struct
pub struct AllocationCode<'fd> {
    /// The file descriptor to map and the configuration for the mapping
    mappable: MappableFd<BorrowedFd<'fd>>,
    /// Cached fstat(2)/fstatfs(2) results for the file descriptor
    stat: Quickstat<BorrowedFd<'fd>>,
    /// Ownership state of the mapping being assembled
    segment: SegmentLifecycle,
}

impl<'fd> AllocationCode<'fd> {
    /// Entry point implementing [MappableFd::mmap]: set up the state machine
    /// and run [Self::mmap_impl].
    pub fn mmap(mappable: MappableFd<BorrowedFd<'fd>>) -> Result<MappedSegment, MMapError> {
        let stat = Quickstat::new(mappable.fd().copy());
        let segment = SegmentLifecycle::None;
        let mut me = Self {
            mappable,
            stat,
            segment,
        };
        me.mmap_impl()
    }

    /// Memory allocation algorithm
    fn mmap_impl(&mut self) -> Result<MappedSegment, MMapError> {
        // Ensure that the fstat(2)/fstatfs(2) call happens now so we report errors early
        // we will need the information later
        self.stat.prefetch()?;

        self.harden_file_descriptor()?;

        self.allocate_guard_page()?;
        self.allocate_data_page()?;

        self.harden_mapped_segment()?;

        Ok(self.segment.take_data_page().unwrap())
    }

    /// Apply memory-level hardening to the data page
    fn harden_mapped_segment(&mut self) -> Result<(), MMapError> {
        self.mlock()?;
        self.madvise()?;

        Ok(())
    }

    /// Apply file-descriptor-level hardening
    fn harden_file_descriptor(&mut self) -> Result<(), MMapError> {
        // memfd_secret(2) does not support MAP_PRIVATE in mmap(2)
        if self.stat.is_memfd_secret()? && !self.config().shared {
            Err(MMapInvalidConfigError::MapSharedNeededForMemfdSecret)?;
        }

        self.enforce_mandatory_memfd_secret_resize_settings()?;
        self.appropriately_size_and_seal_fd()?;

        Ok(())
    }

    /// Advise the kernel that the memory pages must neither be inherited
    /// by child processes on fork(2) nor be included in memory dumps.
    ///
    /// SAFETY:
    ///
    /// * The pointer came directly from mmap, so it is valid and owned exclusively
    ///   by us and retains provenance.
    /// * The length is the mapping's exact length; madvise operates on
    ///   whole pages and rounds to the page's length.
    /// * MADV_DONTFORK and MADV_DONTDUMP only manipulate virtual memory flags; they
    ///   do not change the underlying fd or data in memory.
    fn madvise(&mut self) -> Result<(), MMapError> {
        use rustix::mm::{Advice, madvise};

        use Advice::{LinuxDontDump as ADump, LinuxDontFork as AFork};
        use MMapError::{
            CouldNotProtectAgainstForks as EFork, CouldNotProtectAgainstMemoryDumps as EDump,
        };

        let seg = self.data_page()?;
        let (addr, len) = (seg.ptr().cast(), seg.len);
        unsafe {
            madvise(addr, len, AFork).map_err(EFork)?;
            madvise(addr, len, ADump).map_err(EDump)?;
        }

        Ok(())
    }

    /// mlock(2) the memory region into memory (prevent swapping)
    /// after mapping the page into memory
    ///
    /// We do not mlock(2) the memory in two cases:
    ///
    /// - The backing file descriptor is memfd_secret(2), as the semantics of memfd_secret(2)
    ///   automatically lock all memfd_secret(2) derived pages into memory
    /// - The mapping is unreadable, in which case [rustix::mm::mlock] documents
    ///   that mlock is not supported on unreadable mappings
    ///
    /// SAFETY:
    ///
    /// * The pointer came directly from mmap, so it retains the mapping's
    ///   provenance.
    /// * mmap returns a page-aligned mapping address.
    /// * POSIX mmap operates on whole pages, so the page-rounded range
    ///   touched by mlock is part of this mapping.
    /// * PROT_READ makes the range readable, satisfying rustix's
    ///   documented mlock precondition. PROT_READ is set, because we check for
    ///   `self.config().unreadable` explicitly.
    fn mlock(&mut self) -> Result<(), MMapError> {
        if self.stat.is_memfd_secret()? || self.config().unreadable {
            return Ok(());
        }

        let seg = self.data_page()?;
        unsafe { rustix::mm::mlock(seg.ptr().cast(), seg.len()).map_err(MMapError::MLockError)? };

        Ok(())
    }

    /// Ensure the data page has been mapped and return a mutable reference to
    /// the owned segment; convenience wrapper around [Self::allocate_data_page]
    fn data_page(&mut self) -> Result<&mut MappedSegment, MMapError> {
        self.allocate_data_page()
    }

    /// Map the region into memory, replacing the middle of the guard-page
    /// reservation with the file-descriptor mapping
    ///
    /// SAFETY:
    ///
    /// * `ptr` points exactly one page into the guard-page allocation owned
    ///   by the MappedSegment created above, so it is page-aligned and the
    ///   range `ptr .. ptr + len`, rounded up to the page size, lies inside
    ///   that live mapping and is valid to mutate with `ptr`'s provenance.
    /// * MAP_FIXED replaces part of the guard-page allocation we exclusively
    ///   own (via the MappedSegment), so no existing Rust allocation/reference
    ///   is unmapped or replaced; the MappedSegment remains the sole owner of
    ///   the resulting composite region.
    fn allocate_data_page(&mut self) -> Result<&mut MappedSegment, MMapError> {
        use rustix::mm::MapFlags;

        if self.segment.is_data_page() {
            return self.segment.data_page_mut().unwrap().ok();
        }

        self.guard_page()?; // Allocate the guard page if necessary (just in case)
        let segment = self.segment.take_segment().unwrap();

        let res = unsafe {
            let (ptr, len) = (segment.ptr().cast(), segment.len());
            let flags = self.mmap_flags() | MapFlags::FIXED;
            rustix::mm::mmap(ptr, len, self.mmap_prot(), flags, self.fd(), 0)
                .map_err(MMapError::MMapError)
        };

        let segment = match res {
            Ok(_) => self.segment.insert_data_page(segment),
            Err(_) => self.segment.insert_guard_page(segment),
        };

        res?;

        Ok(segment)
    }

    /// Allocate guard pages and prepare the memory region for the actual allocation.
    /// Note that we make sure the guard-page gets deallocated even if the later mmap(2)
    /// call fails by immediately constructing the MappedSegment, which has an appropriate
    /// destructor.
    ///
    /// SAFETY:
    ///
    /// * For mmap_anonymous: the address passed is NULL, so mmap chooses a fresh
    ///   mapping; rustix's non-null input-pointer provenance requirement does
    ///   not apply.
    /// * For the direct construction of [MappedSegment]: `alloc_ptr` is the
    ///   page-aligned start of the fresh anonymous mapping and `alloc_len` is
    ///   its exact length, so the region is contiguous and currently valid. The
    ///   segment `ptr .. ptr + len` is fully contained in
    ///   `alloc_ptr .. alloc_ptr + alloc_len`: `ptr` is exactly one
    ///   page into the allocation and `len <= alloc_len - 2 * pagesize`. The
    ///   mapping was just created by us and no other handle refers to it, so it
    ///   is exclusively owned.
    fn allocate_guard_page(&mut self) -> Result<&mut MappedSegment, MMapError> {
        use rustix::mm::{MapFlags, ProtFlags, mmap_anonymous};

        if self.segment.segment_mut().is_some() {
            return Ok(self.segment.segment_mut().unwrap());
        }

        let segment = unsafe {
            let (prot, flags) = (ProtFlags::empty(), MapFlags::empty()); // PROT_NONE,
            let ptr = mmap_anonymous(null_mut(), self.alloc_len()?, prot, flags)
                .map_err(MMapError::MMapError)?;
            MappedSegment {
                alloc_ptr: ptr,
                alloc_len: self.alloc_len()?,
                ptr: ptr.add(self.pagesize()).cast(),
                len: self.data_len()?,
            }
        };

        self.segment.insert_guard_page(segment).ok()
    }

    /// Resize the file descriptor to the requested size (under
    /// [MMapSizePolicy::Resize]) or verify that it already has the requested
    /// size (under [MMapSizePolicy::Checked]), then seal it against being
    /// grown or shrunken unless resizing protection is disabled or the file
    /// descriptor is a memfd_secret(2).
    ///
    /// Adding seals can race with another party sealing the same file
    /// descriptor, so it is retried a bounded number of times; see
    /// [MemfdCreateSealError] for the failure modes reported to the caller
    fn appropriately_size_and_seal_fd(&mut self) -> Result<(), MMapError> {
        if self.resize_protection_requested() && !self.stat.is_memfd_secret()? {
            let current_seals = rustix::fs::fcntl_get_seals(self.fd())
                .map_err(MemfdCreateSealError::SystemError)?;
            let missing = SRESIZE.difference(current_seals);

            // Unable to add the missing seals, FD is already sealed against adding further seals
            if current_seals.contains(SSEAL) && !missing.is_empty() {
                Err(MemfdCreateSealError::PresealedWithMissingSeals { missing })?;
            }
        }

        if self.data_len()? == 0 {
            return Err(MMapError::ZeroSize);
        }

        // Resize the file descriptor if requested and necessary
        use MMapSizePolicy as P;
        match self.size_policy()? {
            P::Resize(_) => {
                let actual_size = self.stat.size()?;
                if self.data_len_u64()? != actual_size {
                    rustix::fs::ftruncate(self.fd(), self.data_len_u64()?)
                        .map_err(MMapError::ResizeError)?;
                }
            }
            P::Checked(_) => {
                let expected = self.data_len_u64()?;
                let actual = self.stat.size()?;
                if expected != actual {
                    return Err(MMapError::IncorrectSize { expected, actual });
                }
            }
        }

        let mut seal_ctr: usize = usize::MAX;
        let mut prev_seals: Option<SealFlags> = None;
        'seal: loop {
            // Do not protect against resizing if this is disabled
            if !self.resize_protection_requested() {
                break 'seal;

            // No active steps needed to protect memfd_secret based file descriptors
            // against resizing
            } else if self.stat.is_memfd_secret()? {
                break 'seal;
            }

            // Increment the loop counter
            seal_ctr = seal_ctr.overflowing_add(1).0;

            // Abort this loop after too many failed attempts just to be safe
            if seal_ctr >= 16 {
                Err(MemfdCreateSealError::RetriesAborted)?;
            }

            // Add the seals
            //
            // The call succeeding and failing with permission denied are both
            // handled the same way: fetch the list of seals below and check
            // what seals we actually got
            //
            // Permission denied could happen because F_SEAL_SEAL raced in
            // concurrently (detected via the seal set below and reported as
            // PresealedWithMissingSeals), or because the file descriptor is
            // not writable — adding seals requires a writable file descriptor;
            // that case can never make progress and is detected by the
            // no-progress check below
            let add_denied = match rustix::fs::fcntl_add_seals(self.fd(), SRESIZE) {
                Ok(()) => false,
                Err(Errno::PERM) => true,
                // Other error; just propagate this error to the function caller
                Err(errno) => return Err(MemfdCreateSealError::SystemError(errno))?,
            };

            // Figure out what seals are set and which ones we need to add
            let current_seals = rustix::fs::fcntl_get_seals(self.fd())
                .map_err(MemfdCreateSealError::SystemError)?;
            let missing = SRESIZE.difference(current_seals);

            // Unable to add the missing seals, FD is already sealed against adding further seals
            if current_seals.contains(SSEAL) && !missing.is_empty() {
                Err(MemfdCreateSealError::PresealedWithMissingSeals { missing })?;
            }

            // Adding seals was denied and the seal set did not change since the
            // last attempt: no progress is possible (e.g. the file descriptor
            // is not writable), so retrying would merely spin until the retry
            // limit; report the persistent permission error instead
            if add_denied && prev_seals == Some(current_seals) {
                Err(MemfdCreateSealError::SystemError(Errno::PERM))?;
            }
            prev_seals = Some(current_seals);

            // Missing seals, but not sealed against further seals. Try to add the seals we need.
            if !missing.is_empty() {
                continue 'seal;
            }

            // All the seals are present; check the size of the file descriptor again
            // just to make sure that the size is correct. If it's not correct, we raise
            // an error
            let (expected_size, actual_size) =
                (self.data_len_u64()?, Quickstat::new(self.fd()).size()?);
            if expected_size != actual_size {
                Err(MemfdCreateSealError::ResizeRace {
                    expected_size,
                    actual_size,
                })?;
            }

            // Sealing successful; now aborting
            break 'seal;
        }

        Ok(())
    }

    /// Validate that the resizing protection settings match the mandatory settings
    /// with memfd_secret(2)
    fn enforce_mandatory_memfd_secret_resize_settings(&mut self) -> Result<(), MMapError> {
        if !self.stat.is_memfd_secret()? {
            return Ok(());
        }

        let resize_protection_enabled =
            memfd_secret_protects_against_resizing().map_err(MemfdCreateSealError::SystemError)?;
        if self.resize_protection_requested() != resize_protection_enabled {
            Err(MMapInvalidConfigError::IncorrectResizingProtectionSetting {
                protection_enabled_by_system: resize_protection_enabled,
                protection_requested: self.resize_protection_requested(),
            })?;
        }

        Ok(())
    }

    /// Whether the configuration requests protection against resizing
    fn resize_protection_requested(&self) -> bool {
        !self.config().no_resizing_protection
    }

    /// Ensure the backing segment has been allocated and return a mutable
    /// reference to it; convenience wrapper around [Self::allocate_guard_page].
    /// If the data page has already been mapped, the data-page segment is
    /// returned as-is.
    fn guard_page(&mut self) -> Result<&mut MappedSegment, MMapError> {
        self.allocate_guard_page()
    }

    /// Total length of the guard-page reservation: the requested data length
    /// rounded up to a whole number of pages, plus one guard page on either
    /// side
    fn alloc_len(&mut self) -> Result<usize, MMapError> {
        let (pagesize, data_len) = (self.pagesize(), self.data_len()?);
        Ok(data_len.next_multiple_of(pagesize) + 2 * pagesize)
    }

    /// The requested data length as a u64; fails if the configured size can
    /// not be represented as a [usize] (see [Self::data_len])
    fn data_len_u64(&self) -> Result<u64, MMapError> {
        Ok(self.data_len()? as u64)
    }

    // Maximum supported size for data allocations
    fn max_supported_data_len(&self) -> u64 {
        let ps = self.pagesize() as u64;

        // Size must be representable as usize and as u64
        let v = MAX_U64_IN_USIZE;

        // Previous multiple of the page size (will always
        // effectively map fill pages into memory)
        let v = match v.is_multiple_of(ps) {
            true => v,
            false => (v - ps).next_multiple_of(ps),
        };

        // Subtract the two singular guard pages before/after the data
        v - 2 * ps
    }

    /// Retrieve the expected size, raising an error if the
    /// requested_size can not be represented as usize (this should never happen in general,
    /// but it could conceivably be thrown on 32 bit systems when very large mappings (>= 4GB)
    /// are requested
    fn data_len(&self) -> Result<usize, MMapError> {
        let max = self.max_supported_data_len();
        let len = self.size_policy()?.size_value();

        if len > max {
            return Err(MMapError::OutOfBounds {
                requested_len: len,
                max_supported_len: max,
            });
        }

        Ok(len as usize)
    }

    /// A copy of the underlying file descriptor
    fn fd(&self) -> BorrowedFd<'fd> {
        self.mappable.fd().copy()
    }

    /// A copy of the [MapFdConfig] for the mapping
    fn config(&self) -> MapFdConfig {
        self.mappable.config()
    }

    /// The [rustix::mm::ProtFlags] selected by the configuration
    fn mmap_prot(&self) -> rustix::mm::ProtFlags {
        self.config().mmap_prot()
    }

    /// The [rustix::mm::MapFlags] selected by the configuration
    fn mmap_flags(&self) -> rustix::mm::MapFlags {
        self.config().mmap_flags()
    }

    /// The page size of the system
    fn pagesize(&self) -> usize {
        rustix::param::page_size()
    }

    /// The configured [MMapSizePolicy], or [MMapError::MissingSizePolicy] if
    /// none was configured
    fn size_policy(&self) -> Result<MMapSizePolicy, MMapError> {
        self.config()
            .size_policy
            .ok_or(MMapError::MissingSizePolicy)
    }
}

/// Helper for calling fstat in [MappableFd::mmap()]
#[derive(Copy, Clone, Debug)]
struct Quickstat<Fd: AsFd> {
    /// The file descriptor being interrogated
    fd: Fd,
    /// Cached fstat(2) result
    stat: Option<rustix::fs::Stat>,
    /// Cached fstatfs(2) result
    statfs: Option<rustix::fs::StatFs>,
}

impl<Fd: AsFd> Quickstat<Fd> {
    /// New [Quickstat] wrapping the given file descriptor; no system calls
    /// have been issued yet, results are cached on first use
    pub fn new(fd: Fd) -> Self {
        Self {
            fd,
            stat: None,
            statfs: None,
        }
    }

    /// Issue the fstat(2)/fstatfs(2) system calls now (unless already cached)
    /// so that failures are reported early; results are cached for later use
    pub fn prefetch(&mut self) -> Result<(), MMapError> {
        self.stat()?.discard_result();
        self.statfs()?.discard_result();
        Ok(())
    }

    /// fstat(2) the file descriptor (cached)
    pub fn stat(&mut self) -> Result<rustix::fs::Stat, MMapError> {
        if let Some(stat) = self.stat {
            return Ok(stat);
        }

        rustix::fs::fstat(self.fd.as_fd())
            .map_err(MMapError::CouldNotDetermineFileDescriptorInfo)?
            .sideeffect(|stat| {
                self.stat = Some(*stat);
            })
            .ok()
    }

    /// fstatfs(2) the file descriptor (cached)
    pub fn statfs(&mut self) -> Result<rustix::fs::StatFs, MMapError> {
        if let Some(statfs) = self.statfs {
            return Ok(statfs);
        }

        rustix::fs::fstatfs(self.fd.as_fd())
            .map_err(MMapError::CouldNotDetermineFileDescriptorInfo)?
            .sideeffect(|statfs| {
                self.statfs = Some(*statfs);
            })
            .ok()
    }

    /// The size of the file descriptor according to fstat(2)
    pub fn size(&mut self) -> Result<u64, MMapError> {
        let size = self.stat()?.st_size;
        size.try_into()
            .map_err(|err| MMapError::InvalidSize { err, size })
    }

    /// Whether the file descriptor is a memfd_secret(2) file descriptor,
    /// determined via the fstatfs(2) f_type magic
    pub fn is_memfd_secret(&mut self) -> Result<bool, MMapError> {
        use crate::internal::util::rustix::IsMemfdSecretExt;
        self.statfs()?.is_memfd_secret().ok()
    }
}
