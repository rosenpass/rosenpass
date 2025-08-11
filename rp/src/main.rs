#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod cli;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod exchange;
#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod key;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
mod main_supported_platforms;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
fn main() -> anyhow::Result<()> {
    main_supported_platforms::main()
}

#[cfg(not(any(target_os = "linux", target_os = "freebsd")))]
fn main() {
    panic!("Unfortunately, the rp command is currently not supported on your platform. See https://github.com/rosenpass/rosenpass/issues/689 for more information and discussion.")
}
