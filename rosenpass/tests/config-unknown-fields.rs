//! `rosenpass validate` accepts a config file with fields it does not know and names them

#[test]
fn validate_reports_unknown_fields_but_accepts_the_file() -> anyhow::Result<()> {
    let dir = tempfile::tempdir()?;
    let config_file = dir.path().join("peer.toml");
    std::fs::write(
        &config_file,
        r#"
        listen = []

        [[peers]]
        public_key = "/does/not/matter"
        exchange_command = ["wg", "set", "wg0", "peer", "<PEER_ID>", "preshared-key", "/dev/stdin"]
        "#,
    )?;

    let out = test_bin::get_test_bin("rosenpass")
        .args(["validate"])
        .arg(&config_file)
        .output()?;
    let stderr = String::from_utf8(out.stderr)?;

    assert!(out.status.success(), "{stderr}");
    assert!(
        stderr.contains("conforms to the expected schema"),
        "{stderr}"
    );
    assert!(
        stderr.contains("unknown field `peers[0].exchange_command`"),
        "{stderr}"
    );

    Ok(())
}
