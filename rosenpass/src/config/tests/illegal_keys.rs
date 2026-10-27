//! test that illegal keys are rejected at (almost) every level of the config file
//! 
//! - TODO: this module does not yet check ALL deny_illegal_key calls

use super::harness::assert_parse_str_fails_with;

fn test(config: &str) {
    assert_parse_str_fails_with(config, &["illegal key \"garbage\""]);
}

#[test]
fn device() {
    test(
        r#"
[[wireguard-devices]]
garbage = true
"#,
    );
}

#[test]
fn device_wireguard_options() {
    test(
        r#"
[[wireguard-devices]]
create = true
wireguard-options = { garbage = 1 }
"#,
    );
}

#[test]
fn root_without_rosenpass_table() {
    test(
        r#"
garbage = 1
"#,
    );
}

#[test]
fn root_with_rosenpass_table() {
    test(
        r#"
garbage = 1

[rosenpass]
our-keypair = { secret-key-file = "k/pqsk", public-key-file = "k/pqpk" }
"#,
    );
}

#[test]
fn rosenpass_table() {
    test(
        r#"
[rosenpass]
garbage = 1
"#,
    );
}

#[test]
fn peer() {
    test(
        r#"
[[peers]]
garbage = 1
"#,
    );
}

#[test]
fn key_out() {
    test(
        r#"
[[peers]]
key-out = { file = "k/out", garbage = 1 }
"#,
    );
}

#[test]
fn wireguard() {
    test(
        r#"
[[peers]]
wireguard = { device = "wg0", garbage = 1 }
"#,
    );
}

#[cfg(feature = "experiment_api")]
#[test]
fn api() {
    test(
        r#"
[rosenpass.api]
garbage = 1
"#,
    );
}
