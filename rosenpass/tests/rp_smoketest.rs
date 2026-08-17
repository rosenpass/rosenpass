use std::process::Command;

#[cfg(any(target_os = "linux", target_os = "freebsd"))]
#[test]
#[cfg_attr(miri, ignore)] // unsupported operation: extern static `pidfd_spawnp` is not supported by Miri
fn smoketest() -> anyhow::Result<()> {
    let tmpdir = tempfile::tempdir()?;

    let secret = tmpdir.path().join("server.secret");
    let public = tmpdir.path().join("server.public");
    let invalid = tmpdir.path().join("invalid.secret");
    let toml = tmpdir.path().join("config.toml");

    let invalid_config = r#"
        verbose = false
        private_keys_dir = "invliad"

        [[peers]]
        public_keys_dir = "invliad"
    "#;

    // Generate keys
    let status = Command::new(env!("CARGO_BIN_EXE_rp"))
        .args(["genkey", secret.to_str().unwrap()])
        .spawn()?
        .wait()?;
    assert!(status.success());

    // Derive Public keys
    let status = Command::new(env!("CARGO_BIN_EXE_rp"))
        .args(["pubkey", secret.to_str().unwrap(), public.to_str().unwrap()])
        .spawn()?
        .wait()?;
    assert!(status.success());

    // Can not exchange keys using exchange with invalid keys
    let out = Command::new(env!("CARGO_BIN_EXE_rp"))
        .args(["exchange", invalid.to_str().unwrap()])
        .output()?;
    assert!(!out.status.success());

    std::fs::write(toml, invalid_config)?;
    let out = Command::new(env!("CARGO_BIN_EXE_rp"))
        .args([
            "exchange-config",
            tmpdir.path().join("invalid_config").to_str().unwrap(),
        ])
        .output()?;
    assert!(!out.status.success());

    Ok(())
}
