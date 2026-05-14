#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod cli;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod exchange;
#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod key;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
mod main_supported_platforms;

#[cfg(any(target_os = "linux", target_os = "freebsd", target_os = "macos"))]
fn main() -> anyhow::Result<()> {
    main_supported_platforms::main()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd", target_os = "macos")))]
fn main() {
    panic!("Unfortunately, the rp command is currently not supported on your platform. See https://github.com/rosenpass/rosenpass/issues/689 for more information and discussion.")
}
