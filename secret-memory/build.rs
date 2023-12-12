use libc;
use std::io::Error;
use std::ptr::null_mut;

// Example custom build script.
fn main() {
    // 1. check for memfd_secret support
    let fd  = unsafe {
        libc::syscall(libc::SYS_memfd_secret, 0) as i32
    };
    if fd != -1 || if let Some(os_err) = Error::last_os_error().raw_os_error() { os_err != 38 } else { true } {
        // with memfd_secret support
        println!("cargo:rustc-cfg=with_memfd_secret");
    }
    if fd != -1 {
        unsafe {
            libc::close(fd);
        }
    }

    // 2. check for posix_memalign support
    let mut ptr = null_mut();
    let ret = unsafe {
        libc::posix_memalign(&mut ptr, 0x1000, 128)
    };
    if ret == 0 {
        // with posix_memalign support
        println!("cargo:rustc-cfg=with_posix_memalign");
        unsafe { libc::free(ptr); }
    }
}
