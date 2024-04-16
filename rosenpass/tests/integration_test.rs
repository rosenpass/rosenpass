use std::{
    fs::{self, write},
    net::UdpSocket,
    path::PathBuf,
    process::Stdio,
    time::Duration,
};

use clap::Parser;
use rosenpass::{app_server::AppServerTestBuilder, cli::CliArgs};
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
    for port in 1025..=u16::MAX {
        if UdpSocket::bind(("127.0.0.1", port)).is_ok() {
            return Some(port);
        }
    }
    None
}

// check that we can exchange keys
#[test]
#[serial]
fn check_exchange_under_normal() {
    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("exchange");
    fs::create_dir_all(&tmpdir).unwrap();

    let secret_key_paths = [tmpdir.join("secret-key-0"), tmpdir.join("secret-key-1")];
    let public_key_paths = [tmpdir.join("public-key-0"), tmpdir.join("public-key-1")];
    let shared_key_paths = [tmpdir.join("shared-key-0"), tmpdir.join("shared-key-1")];

    // generate key pairs
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

    // start first process, the server
    let port = loop {
        if let Some(port) = find_udp_socket() {
            break port;
        }
    };

    let listen_addr = format!("localhost:{port}");
    let mut server = test_bin::get_test_bin(BIN)
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[0])
        .arg("public-key")
        .arg(&public_key_paths[0])
        .args(["listen", &listen_addr, "verbose", "peer", "public-key"])
        .arg(&public_key_paths[1])
        .arg("outfile")
        .arg(&shared_key_paths[0])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start {BIN}");

    std::thread::sleep(Duration::from_millis(500));

    // start second process, the client
    let mut client = test_bin::get_test_bin(BIN)
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[1])
        .arg("public-key")
        .arg(&public_key_paths[1])
        .args(["verbose", "peer", "public-key"])
        .arg(&public_key_paths[0])
        .args(["endpoint", &listen_addr])
        .arg("outfile")
        .arg(&shared_key_paths[1])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start {BIN}");

    // give them some time to do the key exchange
    std::thread::sleep(Duration::from_secs(2));

    // time's up, kill the childs
    server.kill().unwrap();
    client.kill().unwrap();

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
    let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)
    log_builder.filter_level(log::LevelFilter::Debug);
    log_builder.format_timestamp_nanos();
    log_builder.format(|buf, record| {
        let ts_format = buf.timestamp_nanos().to_string();
        writeln!(
            buf,
            "\x1b[1m{:?}\x1b[0m {}: {}",
            std::thread::current().id(),
            &ts_format[18..],
            record.args()
        )
    });

    let _ = log_builder.try_init();

    //Generate binary with responder with feature integration_test
    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("exchange-dos");
    fs::create_dir_all(&tmpdir).unwrap();

    let secret_key_paths = [tmpdir.join("secret-key-0"), tmpdir.join("secret-key-1")];
    let public_key_paths = [tmpdir.join("public-key-0"), tmpdir.join("public-key-1")];
    let shared_key_paths = [tmpdir.join("shared-key-0"), tmpdir.join("shared-key-1")];

    // generate key pairs
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

    // start first process, the server
    let port = loop {
        if let Some(port) = find_udp_socket() {
            break port;
        }
    };

    let listen_addr = format!("localhost:{port}");

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

    let (server_terminate, server_terminate_rx) = std::sync::mpsc::channel();

    let cli = CliArgs::try_parse_from(
        [server_cmd.get_program()]
            .into_iter()
            .chain(server_cmd.get_args()),
    )
    .unwrap();

    std::thread::spawn(move || {
        cli.command
            .run(Some(
                AppServerTestBuilder::default()
                    .enable_dos_permanently(true)
                    .termination_handler(Some(server_terminate_rx))
                    .build()
                    .unwrap(),
            ))
            .unwrap();
    });

    std::thread::sleep(Duration::from_millis(500));

    // start second process, the client
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

    let (client_terminate, client_terminate_rx) = std::sync::mpsc::channel();

    let cli = CliArgs::try_parse_from(
        [client_cmd.get_program()]
            .into_iter()
            .chain(client_cmd.get_args()),
    )
    .unwrap();

    std::thread::spawn(move || {
        cli.command
            .run(Some(
                AppServerTestBuilder::default()
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
