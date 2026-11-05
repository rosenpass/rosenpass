//! Zero-fill and write-fault-in through Unix kernel copies, without mapped references.

use crate::internal::util::{
    io::{devzero, handle_interrupted},
    rustix::raw_read,
};

/// Failure to completely overwrite a mapping during preparation.
#[derive(Debug, thiserror::Error)]
pub enum PopulateError {
    /// Opening the zero source failed.
    #[error("Could not open /dev/zero: {0}")]
    OpenZero(#[source] rustix::io::Errno),
    /// A kernel copy failed; some earlier bytes may already have been zeroed.
    #[error("Kernel-copy population failed: {0}")]
    ReadFailed(#[source] rustix::io::Errno),
    /// The zero source stopped before the whole mapping was covered.
    #[error("Kernel-copy population made zero progress")]
    UnexpectedEof,
}

/// Populate a memory segment with zeros in such a way that failures
/// to populate the memory are reported as errors instead of raising
/// a signal.
///
/// When memory is allocated from the kernel, it may return unpopulated pages.
/// Once these pages are accessed, the kernel will trap and populate the pages
/// on the fly. There are some scenarios (such as OOM) where lazy population of
/// these pages fails and in this case, the kernel will send a signal, potentially
/// crashing the process.
///
/// This implementation does not populate pages by accessing the memory directly,
/// instead it lets the kernel do the work of accessing the pages (e.g. with a sequence
/// of read(2) calls from /dev/zero); this turns the signal we would have received during
/// population into a handylabel error.
///
/// # Safety
///
/// For nonzero `len`, `ptr` must designate a writable mapped range of at
/// least `len` bytes, kept mapped at the same address throughout the call.
/// The range need not be initialized or resident. The caller must ensure that
/// overwriting it is compatible with all live references and concurrent accesses;
/// no Rust references into the range are constructed here. Use only where the
/// contents may be erased, such as fresh allocations or pre-activation SHM.
pub unsafe fn populate_pages(ptr: *mut u8, len: usize) -> Result<(), PopulateError> {
    use PopulateError as E;

    if len == 0 {
        return Ok(());
    }

    let devzero = devzero().map_err(E::OpenZero)?;
    let mut off = 0;
    while off < len {
        // SAFETY: the caller keeps the writable range alive, and offset/count
        // stay within it (raw_read clamps the count). The kernel writes
        // directly without mapped Rust references.
        let res = handle_interrupted(|| unsafe {
            raw_read(devzero, ptr.wrapping_add(off).cast(), len - off)
        });

        let read_count = match res {
            Ok(0) => return Err(PopulateError::UnexpectedEof),
            Err(e) => return Err(E::ReadFailed(e)),
            Ok(n) => n,
        };

        off += read_count;
    }

    Ok(())
}
