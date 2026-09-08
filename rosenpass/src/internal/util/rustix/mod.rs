//! Extensions to the rustix crate for memory safe operating system interfaces

mod error;
pub use error::*;

mod fd;
pub use fd::*;

mod stat;
pub use stat::*;

#[cfg(target_os = "linux")]
mod syscall;
#[cfg(target_os = "linux")]
pub use syscall::*;

#[cfg(target_os = "linux")]
mod memfd;
#[cfg(target_os = "linux")]
pub use memfd::*;
