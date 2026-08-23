//! This module provides wrappers around the memfdsec and the memsec allocators from the
//! [memsec] crate. The wrappers implement the [Allocator](allocator_api2::alloc::Allocator) trait
//! and can thus be used as a drop in replacement wherever ever this trait is required.

pub mod malloc;
pub mod memfdsec;
