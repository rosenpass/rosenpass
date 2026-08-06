use rosenpass::config::RosenpassConfig;
mod common;
use common::assert_toml_round;

#[test]
fn toml_serialization() -> anyhow::Result<()> {
    #[cfg(feature = "experiment_api")]
    assert_toml_round(
        RosenpassConfig::empty(),
        r#"
        listen = []
        verbosity = "Quiet"
        peers = []

        [api]
        listen_path = []
        listen_fd = []
        stream_fd = []
    "#,
    )?;

    #[cfg(not(feature = "experiment_api"))]
    assert_toml_round(
        RosenpassConfig::empty(),
        r#"
        listen = []
        verbosity = "Quiet"
        peers = []
    "#,
    )?;

    #[cfg(feature = "experiment_api")]
    assert_toml_round(
        RosenpassConfig::from_sk_pk("/my/sk", "/my/pk"),
        r#"
        public_key = "/my/pk"
        secret_key = "/my/sk"
        listen = []
        verbosity = "Quiet"
        peers = []

        [api]
        listen_path = []
        listen_fd = []
        stream_fd = []
    "#,
    )?;

    #[cfg(not(feature = "experiment_api"))]
    assert_toml_round(
        RosenpassConfig::from_sk_pk("/my/sk", "/my/pk"),
        r#"
        public_key = "/my/pk"
        secret_key = "/my/sk"
        listen = []
        verbosity = "Quiet"
        peers = []
    "#,
    )?;

    Ok(())
}
