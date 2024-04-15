use std::{fs, net::UdpSocket, path::PathBuf, process::Stdio, time::Duration};

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
// This test creates a responder (server) with the feature flag "integration_test_dos_exchange". The feature flag posts a semaphore
// (linux) to indicate that the server is under load condition. It also modifies the responders behaviour to be permanently under DoS condition
// once triggered, and makes the DoS mechanism more sensitive to be easily triggered.
// The test also creates a thread to send UDP packets to the server to trigger the DoS condition. The test waits for the server to
// be under load condition and then stops the DoS attack. The test then starts the client (initiator) to exchange keys. The test checks that the keys are exchanged successfully under load condition.
#[test]
fn check_exchange_under_dos() {
    //Generate binary with responder with feature integration_test
    let server_test_bin = test_binary::TestBinary::relative_to_parent(
        "rp-it-dos",
        &PathBuf::from_iter(["Cargo.toml"]),
    )
    .with_feature("integration_test_dos_exchange")
    .build()
    .unwrap();

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

    //Create a semaphore. The server will unblock this semaphore after it is under load condition.
    //There are parameters setup under app_server to remain in load condition once triggered for this test feature.
    let sem_name = b"/rp_integration_test_under_dos\0";
    let sem = unsafe { libc::sem_open(sem_name.as_ptr() as *const i8, libc::O_CREAT, 0o644, 1) };
    unsafe {
        libc::sem_wait(sem);
    }

    // start first process, the server
    let port = loop {
        if let Some(port) = find_udp_socket() {
            break port;
        }
    };
    let listen_addr = format!("localhost:{port}");
    let mut server = std::process::Command::new(server_test_bin)
        .args(["--log-level", "debug"])
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[0])
        .arg("public-key")
        .arg(&public_key_paths[0])
        .args(["listen", &listen_addr, "verbose", "peer", "public-key"])
        .arg(&public_key_paths[1])
        .arg("outfile")
        .arg(&shared_key_paths[0])
        //.stdout(Stdio::null())
        //.stderr(Stdio::null())
        .spawn()
        .expect("Test setup failed- Failed to start {server_bin}");

    //Create a UDP socket for DOS sender
    let socket = UdpSocket::bind("127.0.0.1:0").expect("couldn't bind to address");
    let server_addr = listen_addr.clone();

    //Create thread safe atomic bool to stop the DoS attack
    let stop_dos = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stop_dos_handle = stop_dos.clone();

    //Spawn a thread to send DoS packets
    let dos_attack = std::thread::spawn(move || {
        while stop_dos.load(std::sync::atomic::Ordering::Relaxed) == false {
            let buf = [0; 10];
            socket
                .send_to(&buf, &server_addr)
                .expect("couldn't send data");

            std::thread::sleep(Duration::from_micros(10));
        }
    });

    //Wait till we are under load condition for upto 5 seconds
    let mut ts = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    let now = std::time::SystemTime::now();
    let timeout_absolute = now + Duration::from_secs(5);
    if let Ok(duration) = timeout_absolute.duration_since(std::time::SystemTime::UNIX_EPOCH) {
        ts.tv_sec = duration.as_secs() as libc::time_t;
        ts.tv_nsec = duration.subsec_nanos() as _;
    } else {
        panic!("Test setup failed- Failed to calculate timeout for semaphore");
    }
    let mut failed_wait = false;
    if (unsafe { libc::sem_timedwait(sem, &ts) } == -1) {
        failed_wait = true;
    }
    // Close and unlink the semaphore
    if unsafe { libc::sem_close(sem) } == -1 {
        panic!("Test setup failed- Failed to close semaphore");
    }
    if unsafe { libc::sem_unlink(sem_name.as_ptr() as *const i8) } == -1 {
        panic!("Test setup failed- Failed to unlink semaphore");
    }
    if failed_wait {
        panic!("Failed to wait for semaphore- load condition not reached");
    }

    //Stop DoS attack
    stop_dos_handle.store(true, std::sync::atomic::Ordering::Relaxed);

    // start second process, the client
    let mut client = test_bin::get_test_bin(BIN)
        .args(["--log-level", "debug"])
        .args(["exchange", "secret-key"])
        .arg(&secret_key_paths[1])
        .arg("public-key")
        .arg(&public_key_paths[1])
        .args(["verbose", "peer", "public-key"])
        .arg(&public_key_paths[0])
        .args(["endpoint", &listen_addr])
        .arg("outfile")
        .arg(&shared_key_paths[1])
        //.stdout(Stdio::null())
        //.stderr(Stdio::null())
        .spawn()
        .expect("Failed to start {BIN}");

    // give them some time to do the key exchange under load
    std::thread::sleep(Duration::from_secs(10));

    // time's up, kill the childs
    server.kill().unwrap();
    client.kill().unwrap();
    dos_attack.join().unwrap();

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
