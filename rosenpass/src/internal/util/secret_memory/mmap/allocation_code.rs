//! This entire module is dedicated to the implementation of
//! [super::MappableFd::mmap()]; mod.rs contains the interface,
//! while this file handles all the implementation details of
//! memory allocation.
//!
use std::{
    ffi::c_void,
    mem::ManuallyDrop,
    os::fd::{AsFd, BorrowedFd},
    ptr::null_mut,
};

use rustix::{fs::SealFlags, io::Errno};

use crate::internal::util::{
    convert::TryIntoTypeExt,
    int::u64uint::MAX_U64_IN_USIZE,
    mem::{CopyExt, DiscardResultExt},
    option::SomeExt,
    result::OkExt,
    rustix::{TryStatExt, TryStatFsExt},
    secret_memory::{
        fd::memfd_secret_protects_against_resizing,
        mmap::{
            MMapError, MMapInvalidConfigError, MMapSizePolicy, Mappable, MappedSegment,
            MappingConfig, MemfdCreateSealError,
        },
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
    mappable: Mappable<BorrowedFd<'fd>>,
    /// Whether the file descriptor represents a memfd_secret(2)
    fd_is_memfd_secret: Option<bool>,
    /// Size of this file descriptor
    /// Ownership state of the mapping being assembled
    segment: SegmentLifecycle,
}

impl<'fd> AllocationCode<'fd> {
    /// Entry point implementing [MappableFd::mmap]: set up the state machine
    /// and run [Self::mmap_impl].
    pub fn mmap(mappable: Mappable<BorrowedFd<'fd>>) -> Result<MappedSegment, MMapError> {
        let mut me = Self {
            mappable,
            fd_is_memfd_secret: None,
            segment: SegmentLifecycle::None,
        };
        me.mmap_impl()
    }

    /// Memory allocation algorithm
    fn mmap_impl(&mut self) -> Result<MappedSegment, MMapError> {
        self.validate_configuration()?;
        self.prefetch_file_descriptor_info()?;
        self.harden_file_descriptor()?;
        self.allocate_guard_page()?;
        self.allocate_data_page()?;
        self.harden_mapped_segment()?;

        Ok(self.segment.take_data_page().unwrap())
    }

    /// Validate the configuration
    ///
    /// Used to issue any validation errors as early as possible
    fn validate_configuration(&mut self) -> Result<(), MMapError> {
        self.size_policy()?; // MMapError::MissingSizePolicy
        Ok(())
    }

    /// Prefetch information; this is mainly used to report errors
    /// from fstat(2)/fstatfs(2) calls early
    fn prefetch_file_descriptor_info(&mut self) -> Result<(), MMapError> {
        self.try_load_size_now()?.discard_result(); // The fstat(2) system call
        self.is_memfd_secret()?; // The fstatfs(2) system call

        Ok(())
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
        if self.is_memfd_secret()? && !self.config().shared {
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
        if self.is_memfd_secret()? || self.config().unreadable {
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
        use rustix::mm::{Advice, MapFlags};

        if self.segment.is_data_page() {
            return self.segment.data_page_mut().unwrap().ok();
        }

        self.guard_page()?; // Allocate the guard page if necessary (just in case)
        let segment = ManuallyDrop::new(self.segment.take_segment().unwrap());

        let (ptr, len) = (segment.ptr().cast(), segment.len());
        let flags = self.mmap_flags() | MapFlags::FIXED;

        // There is a bug on some linux version where mmap() may return EINVAL
        // while also deallocating the pages we are replacing with MAP_FIXED.
        // This breaks the POSIX.1-2024 compliance
        let bug_detected = flags.contains(MapFlags::PRIVATE)
            && !flags.contains(MapFlags::SHARED)
            && self.is_memfd_secret()?;
        if bug_detected {
            return Err(MMapError::MMapError(Errno::INVAL));
        }

        let res = unsafe { mmap_maybe_anon(ptr, len, self.mmap_prot(), flags, self.fd(), 0) };

        use Errno as E;
        let err = match res {
            // Everything good. Store the segment, now a data segment and return a reference to it.
            Ok(_) => {
                let seg = self
                    .segment
                    .insert_data_page(ManuallyDrop::into_inner(segment));
                return Ok(seg);
            }
            // mmap(3p) (POSIX.1-2024) specifies that mmap is allowed to unmap the pages
            // we are overwriting, but only on errnos other than these three, so for these
            // three it is safe to just reuse the guard page
            Err(err @ (E::BADF | E::INVAL | E::NOTSUP)) => {
                self.segment
                    .insert_guard_page(ManuallyDrop::into_inner(segment));
                return Err(MMapError::MMapError(err));
            }

            // So on a different error, we do not know whether the pages are present or where
            // unmapped; this requires some complicated logic because we have to handle different
            // parts of the allocation in different ways.
            Err(err) => err, // handled below */
        };

        let data_seg_occupied = match unsafe { rustix::mm::madvise(ptr, len, Advice::Normal) } {
            Ok(()) => Some(true),
            Err(E::NOMEM) => Some(false),
            Err(e) => {
                log::warn!(
                    "Tried to use madvise(ptr={ptr:?}, len={len}, MADV_NORMAL) to test if a memory segment is mapped, \
                    but it returned an unexpected error: {e:?}"
                );
                None
            }
        };

        if data_seg_occupied.unwrap_or(true) {
            log::warn!(
                "Tried to allocate a secret memory segment, but we received an unexpected error ({err}) \
                and there are some pages in place where we tried to add the memory mapping for out data. \
                Unfortunately, by the mmap specification (POSIX.1-2024) we can not know if mmap(3p) has \
                left our initial mapping in place or whether mmap(3p) has unmapped our pages. \
                Therefor, even though we know there are pages mapped in that memory segment, we have no way of knowing \
                whether these are our pages: this could also be a memory segment by another thread who raced to allocate \
                some pages in this area. We therefor are forced to leak these pages of memory.\n\
                This can happen in regular operation, but it should happen rarely. If you see this message often, tell us.\n\
                  May leak up to: {len} bytes of address space without consuming any real memory."
            )
        }

        let head = segment.ptr().cast();
        let tail = segment
            .ptr()
            .wrapping_add(segment.len() - self.pagesize())
            .cast();
        let e1 = unsafe { rustix::mm::munmap(head, self.pagesize()) };
        let e2 = unsafe { rustix::mm::munmap(tail, self.pagesize()) };
        let leak = ((e1.is_err() as usize) + (e2.is_err() as usize)) * self.pagesize();

        if e1.is_err() || e2.is_err() {
            log::warn!("\
                Tried to allocate a secret memory segment, but we received an unexpected error ({err}). \
                In this case we have to treat the guard pages and the data pages of the secret memory segment separately \
                and we need to unmap both guard pages manually. During unmapping of at least one of these pages an error \
                occured:\n\
                  Error from unmapping the head guard page: {e1:?}
                  Error from unmapping the tail guard page: {e2:?}
                  May leak up to: {leak} bytes of address space without consuming any real memory.")
        }

        Err(MMapError::MMapError(err))
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
            // PROT_NONE, MAP_PRIVATE
            let (prot, flags) = (ProtFlags::empty(), MapFlags::PRIVATE);
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
        let Some(fd) = self.fd() else { return Ok(()) };

        if self.resize_protection_requested() && !self.is_memfd_secret()? {
            let current_seals =
                rustix::fs::fcntl_get_seals(fd).map_err(MemfdCreateSealError::SystemError)?;
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
        {
            use MMapSizePolicy as P;
            let (expected, actual) = (self.data_len_u64()?, self.load_size_now()?);
            match (expected == actual, self.size_policy()?) {
                (true, _) => {} // Size is as expected; all good
                (false, P::Resize(_)) => {
                    rustix::fs::ftruncate(fd, expected).map_err(MMapError::ResizeError)?;
                }
                (false, P::Checked(_)) => {
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
            } else if self.is_memfd_secret()? {
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
            let add_denied = match rustix::fs::fcntl_add_seals(fd, SRESIZE) {
                Ok(()) => false,
                Err(Errno::PERM) => true,
                // Other error; just propagate this error to the function caller
                Err(errno) => return Err(MemfdCreateSealError::SystemError(errno))?,
            };

            // Figure out what seals are set and which ones we need to add
            let current_seals =
                rustix::fs::fcntl_get_seals(fd).map_err(MemfdCreateSealError::SystemError)?;
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
            let (expected, actual) = (self.data_len_u64()?, self.load_size_now()?);
            if expected != actual {
                Err(MemfdCreateSealError::ResizeRace { expected, actual })?;
            }

            // Sealing successful; now aborting
            break 'seal;
        }

        Ok(())
    }

    /// Validate that the resizing protection settings match the mandatory settings
    /// with memfd_secret(2)
    fn enforce_mandatory_memfd_secret_resize_settings(&mut self) -> Result<(), MMapError> {
        if !self.is_memfd_secret()? {
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

    /// Check if this allocation is for a memfd_secret(2) FD
    fn is_memfd_secret(&mut self) -> Result<bool, MMapError> {
        if let Some(val) = self.fd_is_memfd_secret {
            return Ok(val);
        }

        let Some(fd) = self.fd() else {
            return Ok(false);
        };

        let val = fd
            .is_memfd_secret()
            .map_err(MMapError::CouldNotDetermineFileDescriptorInfo)?;
        self.fd_is_memfd_secret.insert(val).discard_result();

        Ok(val)
    }

    /// Look up the size of the file represented by the file descriptor we are
    /// mapping into memory.
    ///
    /// Compared to [Self::try_load_size_now()]/[Self::try_size()], this function panics if we
    /// are mapping anonymous memory ([Self::fd()] is `None`), whereas [Self::try_load_size_now()]
    /// panics, whereas [Self::try_load_size_now()]/[Self::try_size()] just return `Ok(None)`.
    fn load_size_now(&mut self) -> Result<u64, MMapError> {
        self.try_load_size_now()?
            .expect("\
                Failed to load size in AllocationCode::appropriately_size_and_seal_fd() after we already \
                checked that the we are operating on a file descriptor, not on anonymous memory. \
                This is a bug!")
            .ok()
    }

    /// Look up the size of the file represented by the file descriptor we are
    /// mapping into memory.
    ///
    /// Compared to [Self::load_size_now()], this function returns `Ok(None)` if we
    /// are mapping anonymous memory ([Self::fd()] is `None`), whereas [Self::load_size_now()]
    /// panics.
    fn try_load_size_now(&mut self) -> Result<Option<u64>, MMapError> {
        let Some(fd) = self.fd() else {
            return Ok(None);
        };

        let size = fd
            .size()
            .map_err(MMapError::CouldNotDetermineFileDescriptorInfo)?;
        size.try_into_type::<u64>()
            .map_err(|err| MMapError::InvalidSize { err, size })?
            .some()
            .ok()
    }

    /// A copy of the underlying file descriptor
    fn fd(&self) -> Option<BorrowedFd<'fd>> {
        self.mappable.fd().map(CopyExt::copy)
    }

    /// A copy of the [MapFdConfig] for the mapping
    fn config(&self) -> MappingConfig {
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

/// Call [rustix::mm::mmap()] or [rustix::mm::mmap_anonymous()] depending on
/// whether the `fd` param is None or a file descriptor
unsafe fn mmap_maybe_anon<Fd: AsFd>(
    ptr: *mut c_void,
    len: usize,
    prot: rustix::mm::ProtFlags,
    flags: rustix::mm::MapFlags,
    fd: Option<Fd>,
    offset: u64,
) -> rustix::io::Result<*mut c_void> {
    use rustix::mm::{mmap, mmap_anonymous};
    match fd {
        Some(fd) => unsafe { mmap(ptr, len, prot, flags, fd, offset) },
        None => unsafe { mmap_anonymous(ptr, len, prot, flags) },
    }
}
