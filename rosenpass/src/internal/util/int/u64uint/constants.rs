//! Constants for u64 <-> usize conversion

/// Largest numeric value that can be safely represented both as
/// a u64 and usize
pub const MAX_USIZE_IN_U64: usize = match u64::BITS >= usize::BITS {
    true => usize::MAX,
    false => u64::MAX as usize,
};

/// Largest numeric value that can be safely represented both as
/// a u64 and usize
pub const MAX_U64_IN_USIZE: u64 = MAX_USIZE_IN_U64 as u64;
