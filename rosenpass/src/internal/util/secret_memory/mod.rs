//! Utilities for allocating secret memory

// The mmap module uses Linux-only interfaces (memfd sealing via fcntl(2),
// fstatfs(2) magic detection); all its consumers ([fd], [crate::internal::util::ipc::shm])
// are Linux-only as well
#[cfg(target_os = "linux")]
pub mod fd;
#[cfg(target_os = "linux")]
pub mod mmap;
