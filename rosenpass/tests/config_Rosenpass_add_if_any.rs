#[cfg(not(feature = "experiment_api"))]
use std::path::PathBuf;

use rosenpass::config::RosenpassConfig;

#[test]
fn config_rosenpass_add_if_any_example() {
    #[cfg(not(feature = "experiment_api"))]
    let mut v = RosenpassConfig::new_minimal(PathBuf::from("secret"), PathBuf::from("public"));
    #[cfg(feature = "experiment_api")]
    let mut v = RosenpassConfig::new_minimal(None, None);

    v.add_if_any(4000);

    assert!(
        v.our_listen_addresses
            .iter()
            .any(|a| format!("{a:?}") == "0.0.0.0:4000")
    );
    assert!(
        v.our_listen_addresses
            .iter()
            .any(|a| format!("{a:?}") == "[::]:4000")
    );
}
