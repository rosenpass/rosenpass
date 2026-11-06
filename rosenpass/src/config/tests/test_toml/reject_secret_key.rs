//! test that secret keys are denied for peers

use super::harness::assert_parse_str_fails_with;

#[test]
fn their_keypair_rejects_secret_key_file() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
their-keypair = { public-key-file = "k/pqpk", secret-key-file = "k/pqsk" }
"#,
        &["illegal key \"secret-key-file\""],
    );
}

#[test]
fn their_keypair_rejects_secret_key_directory() {
    assert_parse_str_fails_with(
        r#"
our-keypair = { secret-key-file = "k/pqsk", public-key-file = "k/pqpk" }

[[peers]]
their-keypair = { public-key-file = "k/pqpk", secret-key-directory = "k" }
"#,
        &["illegal key \"secret-key-directory\""],
    );
}

#[test]
fn peer_rejects_legacy_secret_key() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
public_key = "k/pqpk"
secret_key = "k/pqsk"
"#,
        &["illegal key \"secret_key\""],
    );
}

#[test]
fn their_wireguard_keypair_rejects_secret_key_file() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
wireguard = { device = "wg0", their-wireguard-keypair = { public-key-file = "k/wgpk", secret-key-file = "k/wgsk" } }
"#,
        &["illegal key \"secret-key-file\""],
    );
}
