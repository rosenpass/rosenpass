//! Working with ranges of [super::U64Uint]

use std::ops::Range;

use super::U64USize;

/// Extensions for working with [std::ops::Range] of [U64USize]
pub trait U64USizeRangeExt {
    /// Convert to a usize based range
    fn usize(self) -> Range<usize>;
    /// Convert to a u64 based range
    fn u64(self) -> Range<u64>;
}

impl U64USizeRangeExt for Range<U64USize> {
    fn usize(self) -> Range<usize> {
        Range {
            start: self.start.usize(),
            end: self.end.usize(),
        }
    }

    fn u64(self) -> Range<u64> {
        Range {
            start: self.start.u64(),
            end: self.end.u64(),
        }
    }
}
