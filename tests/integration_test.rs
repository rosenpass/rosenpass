use std::{fs, net::UdpSocket, path::PathBuf, process::Stdio, time::Duration};

const BIN: &str = "rosenpass";

// check that we can generate keys
#[test]
fn generate_keys() {
    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("keygen");
    fs::create_dir_all(&tmpdir).unwrap();

    let priv_key_path = tmpdir.join("private-key");
    let pub_key_path = tmpdir.join("public-key");

    let output = test_bin::get_test_bin(BIN)
        .args(["keygen", "private-key"])
        .arg(&priv_key_path)
        .arg("public-key")
        .arg(&pub_key_path)
        .output()
        .expect("Failed to start {BIN}");

    assert_eq!(String::from_utf8_lossy(&output.stdout), "");

    assert!(priv_key_path.is_file());
    assert!(pub_key_path.is_file());

    // cleanup
    fs::remove_dir_all(&tmpdir).unwrap();
}

fn find_udp_socket() -> u16 {
    for port in 1025..=u16::MAX {
        match UdpSocket::bind(("127.0.0.1", port)) {
            Ok(_) => {
                return port;
            }
            _ => {}
        }
    }
    panic!("no free UDP port found");
}

// check that we can exchange keys
#[test]
fn check_exchange() {
    let tmpdir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("exchange");
    fs::create_dir_all(&tmpdir).unwrap();

    let priv_key_paths = [tmpdir.join("private-key-0"), tmpdir.join("private-key-1")];
    let pub_key_paths = [tmpdir.join("public-key-0"), tmpdir.join("public-key-1")];
    let shared_key_paths = [tmpdir.join("shared-key-0"), tmpdir.join("shared-key-1")];

    // generate key pairs
    for (priv_key_path, pub_key_path) in priv_key_paths.iter().zip(pub_key_paths.iter()) {
        let output = test_bin::get_test_bin(BIN)
            .args(["keygen", "private-key"])
            .arg(&priv_key_path)
            .arg("public-key")
            .arg(&pub_key_path)
            .output()
            .expect("Failed to start {BIN}");

        assert_eq!(String::from_utf8_lossy(&output.stdout), "");
        assert!(priv_key_path.is_file());
        assert!(pub_key_path.is_file());
    }

    // start first process, the server
    let port = find_udp_socket();
    let listen_addr = format!("localhost:{port}");
    let mut server = test_bin::get_test_bin(BIN)
        .args(["exchange", "private-key"])
        .arg(&priv_key_paths[0])
        .arg("public-key")
        .arg(&pub_key_paths[0])
        .args(["listen", &listen_addr, "verbose", "peer", "public-key"])
        .arg(&pub_key_paths[1])
        .arg("outfile")
        .arg(&shared_key_paths[0])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start {BIN}");

    // start second process, the client
    let mut client = test_bin::get_test_bin(BIN)
        .args(["exchange", "private-key"])
        .arg(&priv_key_paths[1])
        .arg("public-key")
        .arg(&pub_key_paths[1])
        .args(["verbose", "peer", "public-key"])
        .arg(&pub_key_paths[0])
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
