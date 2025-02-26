use std::{
    net::SocketAddr,
    ops::DerefMut,
    str::FromStr,
    sync::mpsc,
    thread::{self, sleep},
    time::Duration,
};

use rosenpass::config::ProtocolVersion;
use rosenpass::{
    app_server::{AppServer, AppServerTest, MAX_B64_KEY_SIZE},
    protocol::{SPk, SSk, SymKey},
};
use rosenpass_cipher_traits::kem::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass_util::{file::LoadValueB64, functional::run, mem::DiscardResultExt, result::OkExt};

#[test]
fn key_exchange_with_app_server_v02() -> anyhow::Result<()> {
    key_exchange_with_app_server(ProtocolVersion::V02)
}

#[test]
fn key_exchange_with_app_server_v03() -> anyhow::Result<()> {
    key_exchange_with_app_server(ProtocolVersion::V03)
}

fn key_exchange_with_app_server(protocol_version: ProtocolVersion) -> anyhow::Result<()> {
    let tmpdir = tempfile::tempdir()?;
    let outfile_a = tmpdir.path().join("osk_a");
    let outfile_b = tmpdir.path().join("osk_b");

    // Set security policy for storing secrets; choose the one that is faster for testing
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    // Introduce the servers to each other
    let psk_a = SymKey::random();
    let psk_b = psk_a.clone();

    let (tx_a, rx_b) = mpsc::sync_channel(1);
    let (tx_b, rx_a) = mpsc::sync_channel(1);

    let (tx_term_a, rx_term_a) = mpsc::channel();
    let (tx_term_b, rx_term_b) = mpsc::channel();

    let configs = [
        (false, outfile_a.clone(), psk_a, tx_a, rx_a, rx_term_a),
        (true, outfile_b.clone(), psk_b, tx_b, rx_b, rx_term_b),
    ];

    for (is_client, osk, psk, tx, rx, rx_term) in configs {
        thread::spawn(move || {
            run(move || -> anyhow::Result<()> {
                let mut srv = TestServer::new(rx_term)?;

                tx.send((srv.loopback_port()?, srv.public_key()?.clone()))?;
                let (otr_port, otr_pk) = rx.recv()?;

                let psk = Some(psk);
                let broker_peer = None;
                let pk = otr_pk;
                let outfile = Some(osk);
                let port = otr_port;
                let hostname = is_client.then(|| format!("[::1]:{port}"));
                srv.app_srv.add_peer(
                    psk,
                    pk,
                    outfile,
                    broker_peer,
                    hostname,
                    protocol_version.clone(),
                )?;

                srv.app_srv.event_loop()
            })
            .unwrap();
        });
    }

    // Busy wait for both keys to be exchanged
    let mut successful_exchange = false;
    for _ in 0..2000 {
        // 40s
        sleep(Duration::from_millis(20));
        run(|| -> anyhow::Result<()> {
            let osk_a = SymKey::load_b64::<MAX_B64_KEY_SIZE, _>(&outfile_a)?;
            let osk_b = SymKey::load_b64::<MAX_B64_KEY_SIZE, _>(&outfile_b)?;
            successful_exchange = rosenpass_constant_time::memcmp(osk_a.secret(), osk_b.secret());
            Ok(())
        })
        .discard_result();
        if successful_exchange {
            break;
        }
    }

    // Tell the parties to terminate
    tx_term_a.send(())?;
    tx_term_b.send(())?;

    assert!(
        successful_exchange,
        "Test did not complete successfully within the deadline"
    );

    Ok(())
}

struct TestServer {
    app_srv: AppServer,
}

impl TestServer {
    fn new(termination_queue: mpsc::Receiver<()>) -> anyhow::Result<Self> {
        let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
        StaticKem::keygen(sk.secret_mut(), pk.deref_mut())?;

        let keypair = Some((sk, pk));
        let addrs = vec![
            SocketAddr::from_str("[::1]:0")?, // Localhost, any port. For connecting to the test server.
                                              // ipv4_any_binding(), // any IPv4 interface
                                              // ipv6_any_binding(), // any IPv6 interface
        ];
        let verbosity = rosenpass::config::Verbosity::Verbose;
        let test_helpers = Some(AppServerTest {
            enable_dos_permanently: false,
            termination_handler: Some(termination_queue),
        });

        let app_srv = AppServer::new(keypair, addrs, verbosity, test_helpers)?;

        Self { app_srv }.ok()
    }

    fn loopback_port(&self) -> anyhow::Result<u16> {
        self.app_srv.sockets[0].local_addr()?.port().ok()
    }

    fn public_key(&self) -> anyhow::Result<&SPk> {
        Ok(&self.app_srv.crypto_server()?.spkm)
    }
}
