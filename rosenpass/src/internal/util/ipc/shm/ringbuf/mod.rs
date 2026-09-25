//! Shared-memory ring buffers
//!
//! (Work in progress; lots of functionality for process-local
//! ring buffers has been added, but no cross-process functionality
//! has been added yet)

mod main;
pub use main::*;

mod local;
pub use local::*;
