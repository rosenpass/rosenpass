use std::process::Command;

#[test]
fn test_gen_ipc_msg_types() -> anyhow::Result<()> {
    let out = Command::new(env!("CARGO_BIN_EXE_rosenpass-gen-ipc-msg-types")).output()?;
    assert!(out.status.success());

    let stdout = String::from_utf8(out.stdout)?;

    // Smoke tests only
    assert!(stdout.contains("type RawMsgType = u128;"));
    // For Blake2b:
    assert!(stdout.contains("const SUPPLY_KEYPAIR_RESPONSE : RawMsgType = RawMsgType::from_le_bytes(hex!(\"f2dc 49bd e261 5f10    40b7 3c16 ec61 edb9\"));"));
    // For SHAKE256:
    assert!(stdout.contains("const SUPPLY_KEYPAIR_RESPONSE : RawMsgType = RawMsgType::from_le_bytes(hex!(\"ff80 3886 68a4 47ce    2ae6 0915 0972 682f\"))"));

    // TODO: Also test SHAKE256 here
    Ok(())
}
