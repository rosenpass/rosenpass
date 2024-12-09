#[test]
fn main_fn_prints_errors() -> anyhow::Result<()> {
    let out = test_bin::get_test_bin("rosenpass")
        .args(["exchange-config", "/"])
        .output()?;
    assert!(!out.status.success());
    assert!(String::from_utf8(out.stderr)?.contains("Is a directory (os error 21)"));

    Ok(())
}
