//! Real CLI-server coverage through the public synchronous client.

use anyhow::{Context, bail};
use rosenpass::{api, config};
use std::{
    fs::File,
    net::UdpSocket,
    os::unix::net::UnixStream,
    path::PathBuf,
    process::{Child, Command, Stdio},
    thread::sleep,
    time::{Duration, Instant},
};

#[test]
fn api_client_endpoints_legacy() -> anyhow::Result<()> {
    let mut server = Server::start()?;
    let mut client = server.connect()?;
    exercise_endpoints(&mut client, &server.keys).with_context(|| server.diagnostics())
}

#[cfg(target_os = "linux")]
#[test]
fn api_client_endpoints_after_upgrade() -> anyhow::Result<()> {
    let mut server = Server::start()?;
    let mut client = server.connect()?;
    client
        .upgrade_transport(4096 * 4)
        .with_context(|| server.diagnostics())?;
    exercise_endpoints(&mut client, &server.keys).with_context(|| server.diagnostics())
}

/// Calls every endpoint except UpgradeTransport; the connection may use either transport.
fn exercise_endpoints(client: &mut api::ApiClient, keys: &config::Keypair) -> anyhow::Result<()> {
    // Ping
    assert_ping_echoes(client, 1)?;

    // AddListenSocket
    client.add_listen_socket(UdpSocket::bind("127.0.0.1:0")?)?;

    // AddPskBroker
    let (_broker_peer, broker_server) = UnixStream::pair()?;
    client.add_psk_broker(broker_server)?;

    // SupplyKeypair
    supply_keypair(client, keys)?;

    // A refused request leaves the connection usable
    assert!(supply_keypair(client, keys).is_err());
    assert_ping_echoes(client, 2)
}

/// Each call should use a distinct `fill`, so a stale echo cannot pass.
fn assert_ping_echoes(client: &mut api::ApiClient, fill: u8) -> anyhow::Result<()> {
    let challenge = [fill; 256];
    assert_eq!(client.ping(challenge)?, challenge);
    Ok(())
}

/// Opens the key files afresh on each call, so the server reads them from the start.
fn supply_keypair(client: &mut api::ApiClient, keys: &config::Keypair) -> anyhow::Result<()> {
    client.supply_keypair(File::open(&keys.secret_key)?, File::open(&keys.public_key)?)
}

/// A `rosenpass exchange-config` subprocess serving the API on a socket in a temporary directory
struct Server {
    child: Child,
    socket: PathBuf,
    stderr: PathBuf,
    keys: config::Keypair,
    _dir: tempfile::TempDir,
}

impl Server {
    fn start() -> anyhow::Result<Self> {
        // Set up the environment
        let dir = tempfile::Builder::new()
            .prefix("rosenpass_test_client_endpoints")
            .tempdir()?;

        // Cache names of important files
        let [socket, stderr, pk, sk] =
            ["api.sock", "stderr", "public_key", "secret_key"].map(|name| dir.path().join(name));

        // Generate the Rosenpass keys
        rosenpass::cli::testing::generate_and_save_keypair(sk.clone(), pk.clone())?;
        let keys = config::Keypair::new(pk, sk);

        // Setup the configuration for the subprocess
        let config = config::Rosenpass {
            config_file_path: dir.path().join("config"),
            keypair: None,
            listen: vec![],
            peers: vec![],
            verbosity: config::Verbosity::Verbose,
            api: api::config::ApiConfig {
                listen_path: vec![socket.clone()],
                listen_fd: vec![],
                stream_fd: vec![],
            },
        };
        config.commit()?;

        // Start the subprocess
        let child = Command::new(env!("CARGO_BIN_EXE_rosenpass"))
            .arg("exchange-config")
            .arg(&config.config_file_path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(File::create(&stderr)?)
            .spawn()?;

        Ok(Self {
            child,
            socket,
            stderr,
            keys,
            _dir: dir,
        })
    }

    /// Waits until the server accepts API connections
    fn connect(&mut self) -> anyhow::Result<api::ApiClient> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(status) = self.child.try_wait()? {
                bail!(
                    "server exited during startup: {status}\n{}",
                    self.diagnostics()
                );
            }
            match api::ApiClient::connect(&self.socket) {
                Ok(client) => return Ok(client),
                Err(error) if Instant::now() >= deadline => {
                    bail!(
                        "API startup deadline exceeded: {error}\n{}",
                        self.diagnostics()
                    )
                }
                Err(_) => sleep(Duration::from_millis(20)),
            }
        }
    }

    fn diagnostics(&self) -> String {
        let stderr = std::fs::read_to_string(&self.stderr).unwrap_or_else(|e| e.to_string());
        format!("server stderr: {stderr}")
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        if std::thread::panicking() {
            eprintln!("{}", self.diagnostics());
        }
    }
}
