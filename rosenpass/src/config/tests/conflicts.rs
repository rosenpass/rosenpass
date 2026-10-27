//! tests that mutually exclusive config items are rejected when used together

use super::harness::assert_parse_str_fails_with;

// ============================== key sources (file vs. directory vs. inline) ==============================

#[test]
fn our_keypair_secret_key_file_and_directory() {
    assert_parse_str_fails_with(
        r#"our-keypair = { secret-key-file = "k/pqsk", secret-key-directory = "k", public-key-file = "k/pqpk" }"#,
        &["keys \"secret-key-file\" and \"secret-key-directory\" are mutually exclusive"],
    );
}

#[test]
fn our_keypair_public_key_file_and_directory() {
    assert_parse_str_fails_with(
        r#"our-keypair = { secret-key-file = "k/pqsk", public-key-file = "k/pqpk", public-key-directory = "k" }"#,
        &["keys \"public-key-file\" and \"public-key-directory\" are mutually exclusive"],
    );
}

#[test]
fn preshared_key_file_and_directory() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
preshared-key = { file = "k/psk", directory = "k" }
"#,
        &["keys \"file\" and \"directory\" are mutually exclusive"],
    );
}

// ============================== legacy vs. modern ==============================

#[test]
fn legacy_keypair_and_modern_our_keypair() {
    assert_parse_str_fails_with(
        r#"
secret_key = "k/pqsk"
public_key = "k/pqpk"
our-keypair = { secret-key-file = "k/pqsk", public-key-file = "k/pqpk" }
"#,
        &["can not be used together with \"our-keypair\""],
    );
}

#[test]
fn legacy_secret_key_and_modern_our_keypair() {
    assert_parse_str_fails_with(
        r#"
secret_key = "k/pqsk"
our-keypair = { secret-key-file = "k/pqsk", public-key-file = "k/pqpk" }
"#,
        &["keys \"secret_key\" and \"our-keypair\" are mutually exclusive"],
    );
}

#[test]
fn legacy_public_key_and_modern_our_keypair() {
    assert_parse_str_fails_with(
        r#"
public_key = "k/pqpk"
our-keypair = { secret-key-file = "k/pqsk", public-key-file = "k/pqpk" }
"#,
        &["keys \"public_key\" and \"our-keypair\" are mutually exclusive"],
    );
}

#[test]
fn legacy_peer_public_key_and_their_keypair() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
public_key = "k/pqpk"
their-keypair = { public-key-file = "k/pqpk" }
"#,
        &["keys \"public_key\" and \"their-keypair\" are mutually exclusive"],
    );
}

#[test]
fn legacy_pre_shared_key_and_preshared_key() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
public_key = "k/pqpk"
pre_shared_key = "k/psk"
preshared-key = { file = "k/psk" }
"#,
        &[r#"keys "pre_shared_key" and "preshared-key" exclude each other"#],
    );
}

#[test]
fn legacy_key_out_and_key_out_table() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
key_out = "k/out"
key-out = { file = "k/out" }
"#,
        &["conflicting keys \"key_out\" and \"key-out\""],
    );
}

#[test]
fn legacy_osk_organization_and_osk_table() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
osk_organization = "my.org"
osk-domain-separator = { organization = "my.org", labels = ["My App"] }
"#,
        &["keys \"osk_organization\" and \"osk-domain-separator\" are mutually exclusive"],
    );
}

#[test]
fn legacy_osk_label_and_osk_table() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
osk_label = ["My App"]
osk-domain-separator = { organization = "my.org", labels = ["My App"] }
"#,
        &["keys \"osk_label\" and \"osk-domain-separator\" are mutually exclusive"],
    );
}

/// TODO: this is not exhaustive...
#[test]
fn legacy_wireguard_items_and_modern_wireguard_table() {
    assert_parse_str_fails_with(
        r#"
[[peers]]
public_key = "k/pqpk"
device = "wg0"
wireguard = { device = "wg0" }
"#,
        &["conflicting keys: \"wireguard\" is not compatible with legacy wireguard keys"],
    );
}
