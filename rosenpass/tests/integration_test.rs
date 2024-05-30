use std::{
    fs,
    net::UdpSocket,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use clap::Parser;
use rosenpass::{app_server::AppServerTestBuilder, cli::CliArgs};
use rosenpass_secret_memory::{Public, Secret};
use rosenpass_wireguard_broker::{WireguardBrokerMio, WG_KEY_LEN, WG_PEER_LEN};
use serial_test::serial;
use std::io::Write;

const BIN: &str = "rosenpass";

// check that we can generate keys
#[test]
fn generate_keys() {
    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("keygen");
    fs::create_dir_all(&tmpdir).unwrap();

    let secret_key_path = tmpdir.join("secret-key");
    let public_key_path = tmpdir.join("public-key");

    let output = test_bin::get_test_bin(BIN)
        .args(["gen-keys", "--secret-key"])
        .arg(&secret_key_path)
        .arg("--public-key")
        .arg(&public_key_path)
        .output()
        .expect("Failed to start {BIN}");

    assert_eq!(String::from_utf8_lossy(&output.stdout), "");

    assert!(secret_key_path.is_file());
    assert!(public_key_path.is_file());

    // cleanup
    fs::remove_dir_all(&tmpdir).unwrap();
}

fn find_udp_socket() -> Option<u16> {
    (1025..=u16::MAX).find(|&port| UdpSocket::bind(("::1", port)).is_ok())
}

fn setup_logging() {
    let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)
    log_builder.filter_level(log::LevelFilter::Debug);
    log_builder.format_timestamp_nanos();
    log_builder.format(|buf, record| {
        let ts_format = buf.timestamp_nanos().to_string();
        writeln!(
            buf,
            "\x1b[1m{:?}\x1b[0m {}: {}",
            std::thread::current().id(),
            &ts_format[14..],
            record.args()
        )
    });

    let _ = log_builder.try_init();
}

fn generate_key_pairs(secret_key_paths: &[PathBuf], public_key_paths: &[PathBuf]) {
    for (secret_key_path, pub_key_path) in secret_key_paths.iter().zip(public_key_paths.iter()) {
        let output = test_bin::get_test_bin(BIN)
            .args(["gen-keys", "--secret-key"])
            .arg(secret_key_path)
            .arg("--public-key")
            .arg(pub_key_path)
            .output()
            .expect("Failed to start {BIN}");

        assert_eq!(String::from_utf8_lossy(&output.stdout), "");
        assert!(secret_key_path.is_file());
        assert!(pub_key_path.is_file());
    }
}

fn run_server_client_exchange(
    (server_cmd, server_test_builder): (&std::process::Command, AppServerTestBuilder),
    (client_cmd, client_test_builder): (&std::process::Command, AppServerTestBuilder),
) {
    let (server_terminate, server_terminate_rx) = std::sync::mpsc::channel();
    let (client_terminate, client_terminate_rx) = std::sync::mpsc::channel();

    let cli = CliArgs::try_parse_from(
        [server_cmd.get_program()]
            .into_iter()
            .chain(server_cmd.get_args()),
    )
    .unwrap();

    std::thread::spawn(move || {
        cli.command
            .run(Some(
                server_test_builder
                    .termination_handler(Some(server_terminate_rx))
                    .build()
                    .unwrap(),
            ))
            .unwrap();
    });

    let cli = CliArgs::try_parse_from(
        [client_cmd.get_program()]
            .into_iter()
            .chain(client_cmd.get_args()),
    )
    .unwrap();

    std::thread::spawn(move || {
        cli.command
            .run(Some(
                client_test_builder
                    .termination_handler(Some(client_terminate_rx))
                    .build()
                    .unwrap(),
            ))
            .unwrap();
    });

    // give them some time to do the key exchange under load
    std::thread::sleep(Duration::from_secs(10));

    // time's up, kill the childs
    server_terminate.send(()).unwrap();
    client_terminate.send(()).unwrap();
}

// check that we can exchange keys
#[test]
#[serial]
fn check_exchange_under_normal() {
    setup_logging();

    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("exchange");
    fs::create_dir_all(&tmpdir).unwrap();

    let secret_key_paths = [tmpdir.join("secret-key-0"), tmpdir.join("secret-key-1")];
    let public_key_paths = [tmpdir.join("public-key-0"), tmpdir.join("public-key-1")];
    let shared_key_paths = [tmpdir.join("shared-key-0"), tmpdir.join("shared-key-1")];

    // generate key pairs
    generate_key_pairs(&secret_key_paths, &public_key_paths);

    // start first process, the server
    let port = loop {
        if let Some(port) = find_udp_socket() {
            break port;
        }
    };

    let listen_addr = format!("::1:{port}");
    let mut server_cmd = std::process::Command::new(BIN);

    server_cmd
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[0])
        .arg("public-key")
        .arg(&public_key_paths[0])
        .args(["listen", &listen_addr, "verbose", "peer", "public-key"])
        .arg(&public_key_paths[1])
        .arg("outfile")
        .arg(&shared_key_paths[0]);

    let server_test_builder = AppServerTestBuilder::default();

    let mut client_cmd = std::process::Command::new(BIN);
    client_cmd
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[1])
        .arg("public-key")
        .arg(&public_key_paths[1])
        .args(["verbose", "peer", "public-key"])
        .arg(&public_key_paths[0])
        .args(["endpoint", &listen_addr])
        .arg("outfile")
        .arg(&shared_key_paths[1]);

    let client_test_builder = AppServerTestBuilder::default();

    run_server_client_exchange(
        (&server_cmd, server_test_builder),
        (&client_cmd, client_test_builder),
    );

    // read the shared keys they created
    let shared_keys: Vec<_> = shared_key_paths
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect();

    // check that they created two equal keys
    assert_eq!(shared_keys.len(), 2);
    assert_eq!(shared_keys[0], shared_keys[1]);

    // cleanup
    fs::remove_dir_all(&tmpdir).unwrap();
}

// check that we can trigger a DoS condition  and we can exchange keys under DoS
// This test creates a responder (server) with the feature flag "integration_test_always_under_load" to always be under load condition for the test.
#[test]
#[serial]
fn check_exchange_under_dos() {
    setup_logging();

    //Generate binary with responder with feature integration_test
    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("exchange-dos");
    fs::create_dir_all(&tmpdir).unwrap();

    let secret_key_paths = [tmpdir.join("secret-key-0"), tmpdir.join("secret-key-1")];
    let public_key_paths = [tmpdir.join("public-key-0"), tmpdir.join("public-key-1")];
    let shared_key_paths = [tmpdir.join("shared-key-0"), tmpdir.join("shared-key-1")];

    // generate key pairs
    generate_key_pairs(&secret_key_paths, &public_key_paths);

    // start first process, the server
    let port = loop {
        if let Some(port) = find_udp_socket() {
            break port;
        }
    };

    let listen_addr = format!("::1:{port}");

    let mut server_cmd = std::process::Command::new(BIN);

    server_cmd
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[0])
        .arg("public-key")
        .arg(&public_key_paths[0])
        .args(["listen", &listen_addr, "verbose", "peer", "public-key"])
        .arg(&public_key_paths[1])
        .arg("outfile")
        .arg(&shared_key_paths[0]);

    let server_test_builder = AppServerTestBuilder::default().enable_dos_permanently(true);

    let mut client_cmd = std::process::Command::new(BIN);
    client_cmd
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[1])
        .arg("public-key")
        .arg(&public_key_paths[1])
        .args(["verbose", "peer", "public-key"])
        .arg(&public_key_paths[0])
        .args(["endpoint", &listen_addr])
        .arg("outfile")
        .arg(&shared_key_paths[1]);

    let client_test_builder = AppServerTestBuilder::default();

    run_server_client_exchange(
        (&server_cmd, server_test_builder),
        (&client_cmd, client_test_builder),
    );

    // read the shared keys they created
    let shared_keys: Vec<_> = shared_key_paths
        .iter()
        .map(|p| fs::read_to_string(p).unwrap())
        .collect();

    // check that they created two equal keys
    assert_eq!(shared_keys.len(), 2);
    assert_eq!(shared_keys[0], shared_keys[1]);

    // cleanup
    fs::remove_dir_all(&tmpdir).unwrap();
}

#[allow(dead_code)]
#[derive(Debug, Default)]
struct MockBrokerInner {
    psk: Option<Secret<WG_KEY_LEN>>,
    peer_id: Option<Public<WG_PEER_LEN>>,
    interface: Option<String>,
}

#[derive(Debug, Default)]
struct MockBroker {
    inner: Arc<Mutex<MockBrokerInner>>,
}

impl WireguardBrokerMio for MockBroker {
    type MioError = anyhow::Error;

    fn register(
        &mut self,
        _registry: &mio::Registry,
        _token: mio::Token,
    ) -> Result<(), Self::MioError> {
        Ok(())
    }

    fn process_poll(&mut self) -> Result<(), Self::MioError> {
        Ok(())
    }

    fn unregister(&mut self, _registry: &mio::Registry) -> Result<(), Self::MioError> {
        Ok(())
    }
}

impl rosenpass_wireguard_broker::WireGuardBroker for MockBroker {
    type Error = anyhow::Error;

    fn set_psk(
        &mut self,
        config: rosenpass_wireguard_broker::SerializedBrokerConfig<'_>,
    ) -> Result<(), Self::Error> {
        loop {
            let mut lock = self.inner.try_lock();

            if let Ok(ref mut mutex) = lock {
                **mutex = MockBrokerInner {
                    psk: Some(config.psk.clone()),
                    peer_id: Some(config.peer_id.clone()),
                    interface: Some(std::str::from_utf8(config.interface).unwrap().to_string()),
                };
                break Ok(());
            }
        }
    }
}
