//! tests for the `[rosenpass.api]` table

use super::harness::{ExpectSilent, assert_parse_str_fails_with, parse_string};

/// helper function preparing a minium example config with the given content
fn prepare_api_config(content: &str) -> String {
    format!(
        r#"
[rosenpass]
our-keypair = {{ secret-key-file = "foo", public-key-file = "bar" }}
listen = ["0.0.0.0:9999"]

{content}

[[peers]]
their-keypair = {{ public-key-file = "baz" }}
"#,
    )
}

#[test]
fn read_api_config() -> Result<(), anyhow::Error> {
    let (config, _warnings) = parse_string(prepare_api_config(
        r#"
[rosenpass.api]
listen-path = ["/tmp/rp-api.sock"]
listen-fd = [3]
stream-fd = [4]"#,
    ))
    .expect_silent("parser returned errors");
    assert_eq!(
        config.api.listen_path,
        vec![std::path::PathBuf::from("/tmp/rp-api.sock")]
    );
    assert_eq!(config.api.listen_fd, vec![3]);
    assert_eq!(config.api.stream_fd, vec![4]);
    Ok(())
}

#[test]
fn api_config_as_inline_table() -> Result<(), anyhow::Error> {
    let (config, _warnings) = parse_string(prepare_api_config(
        r#"api = { listen-path = ["/tmp/rp-api.sock"], listen-fd = [3, 7], stream-fd = [4] }"#,
    ))
    .expect_silent("parser returned errors");
    assert_eq!(
        config.api.listen_path,
        vec![std::path::PathBuf::from("/tmp/rp-api.sock")]
    );
    assert_eq!(config.api.listen_fd, vec![3, 7]);
    assert_eq!(config.api.stream_fd, vec![4]);
    Ok(())
}

#[test]
fn api_config_empty_table() {
    assert_parse_str_fails_with(
        prepare_api_config("api = {}"),
        &[
            "require key \"listen-path\"",
            "require key \"listen-fd\"",
            "require key \"stream-fd\"",
        ],
    );
}

#[test]
fn absent_api_passes() {
    let (config, _warnings) =
        parse_string(prepare_api_config("")).expect_silent("parser returned error");
    assert!(config.api.listen_path.is_empty());
    assert!(config.api.listen_fd.is_empty());
    assert!(config.api.stream_fd.is_empty());
}
