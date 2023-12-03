use libc;
use std::io::Error;

// Example custom build script.
fn main() {
    let fd  = unsafe {
        libc::syscall(libc::SYS_memfd_secret, 0) as i32
    };
    if fd != -1 || if let Some(os_err) = Error::last_os_error().raw_os_error() { os_err != 32 } else { true } {
        // with memfd_secret support
        println!("cargo:rustc-cfg=with_memfd_secret");
    }
}
