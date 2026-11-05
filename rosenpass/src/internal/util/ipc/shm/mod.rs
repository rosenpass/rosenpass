//! Resources for working with shared-memory

mod shared_memory_segment;
pub use shared_memory_segment::*;

#[cfg(feature = "experiment_file_descriptor_passing")]
pub mod stream;
