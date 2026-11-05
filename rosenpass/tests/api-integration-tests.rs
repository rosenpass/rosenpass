use std::{net::ToSocketAddrs, os::unix::net::UnixStream, sync::mpsc, thread::sleep, time::Duration};

use anyhow::bail;
use rosenpass::api;
use rosenpass::app_server::AppServerTest;
use rosenpass::internal::util::{
    file::LoadValueB64,
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
    zerocopy::ZerocopySliceExt,
};
use rosenpass_to::{To, ops::copy_slice_least_src};
use serial_test::serial;
use tempfile::TempDir;
use zerocopy::IntoBytes;

use rosenpass::config::{NewFromInner, ProtocolVersion, PublicKeySource};
use rosenpass::protocol::basic_types::SymKey;

fn test_helpers(termination_handler: mpsc::Receiver<()>) -> Option<AppServerTest> {
    Some(AppServerTest {
        enable_dos_permanently: false,
        termination_handler: Some(termination_handler),
        skip_init_logging: true,
    })
}

/// wait until Rosenpass writes its output symmetric key to the given file
fn wait_for_osk(path: &std::path::Path) -> anyhow::Result<SymKey> {
    let mut attempt = 0;
    loop {
        match SymKey::load_b64::<64, _>(path) {
            Ok(osk) => break Ok(osk),
            Err(err) => {
                attempt += 1;
                assert!(
                    attempt < 50,
                    "Peer did not write its output key to {path:?}: {err}"
                );
                sleep(Duration::from_millis(200));
            }
        }
    }
}

#[test]
#[serial]
fn api_integration_test_v02() -> anyhow::Result<()> {
    api_integration_test(ProtocolVersion::V02)
}

#[test]
#[serial]
fn api_integration_test_v03() -> anyhow::Result<()> {
    api_integration_test(ProtocolVersion::V03)
}

fn api_integration_test(protocol_version: ProtocolVersion) -> anyhow::Result<()> {
    let dir = TempDir::with_prefix("rosenpass-api-integration-test")?;

    macro_rules! tempfile {
        ($($lst:expr),+) => {{
            let mut buf =  dir.path().to_path_buf();
            $(buf.push($lst);)*
            buf
        }}
    }

    let peer_a_endpoint = "[::1]:61423";
    let peer_a_osk = tempfile!("a.osk");
    let peer_b_osk = tempfile!("b.osk");

    use rosenpass::config;

    let peer_a_keypair = config::PqKeypairSource {
        secret_key_source: config::SecretPqKeySource::new(config::KeyFromDiskInner::File(
            tempfile!("a.sk"),
        )),
        public_key_source: config::PublicPqKeySource::new(config::KeyFromDiskInner::File(
            tempfile!("a.pk"),
        )),
    };
    let mut peer_a = config::RosenpassConfig::new_minimal(
        Some(peer_a_keypair.secret_key_source.get_key_path()),
        Some(peer_a_keypair.public_key_source.get_key_path()),
    );
    peer_a.our_listen_addresses = peer_a_endpoint.to_socket_addrs()?.collect(); // TODO: This could collide by accident
    peer_a.api.listen_path = vec![tempfile!("a.sock")];
    peer_a.verbosity = config::Verbosity::Verbose;
    peer_a.supported_protocol_versions.clear();
    peer_a.supported_protocol_versions.insert(protocol_version);
    let peer_a_api_path = peer_a.api.listen_path[0].clone();
    peer_a.peers.push(config::PeerConfig {
        name: "a".to_string(),
        enabled: true,
        their_public_key: config::PublicPqKeySource::new(config::KeyFromDiskInner::File(
            tempfile!("b.pk"),
        )),
        endpoint: None,
        preshared_key: None,
        osk_domain_separator: Default::default(),
        output_to_file: Some(config::OutputToFileConfig {
            enabled: true,
            output_file_path: peer_a_osk.clone(),
            osk_domain_separator: Default::default(),
        }),
        wireguard: None,
    });

    let peer_b_keypair = config::PqKeypairSource {
        secret_key_source: config::SecretPqKeySource::new(config::KeyFromDiskInner::File(
            tempfile!("b.sk"),
        )),
        public_key_source: config::PublicPqKeySource::new(config::KeyFromDiskInner::File(
            tempfile!("b.pk"),
        )),
    };
    let mut peer_b = config::RosenpassConfig::new_minimal(
        Some(peer_b_keypair.secret_key_source.get_key_path()),
        Some(peer_b_keypair.public_key_source.get_key_path()),
    );
    peer_b.api.listen_path = vec![tempfile!("b.sock")];
    peer_b.verbosity = config::Verbosity::Verbose;
    peer_b.supported_protocol_versions.clear();
    peer_b.supported_protocol_versions.insert(protocol_version);
    let peer_b_api_path = peer_b.api.listen_path[0].clone();
    peer_b.peers.push(config::PeerConfig {
        name: "b".to_string(),
        enabled: true,
        their_public_key: config::PublicPqKeySource::new(config::KeyFromDiskInner::File(
            tempfile!("a.pk"),
        )),
        endpoint: Some(peer_a_endpoint.to_owned()),
        preshared_key: None,
        osk_domain_separator: Default::default(),
        output_to_file: Some(config::OutputToFileConfig {
            enabled: true,
            output_file_path: peer_b_osk.clone(),
            osk_domain_separator: Default::default(),
        }),
        wireguard: None,
    });

    // Generate the keys
    rosenpass::cli::run::generate_and_save_keypair(
        None,
        &peer_a_keypair.secret_key_source.get_key_path(),
        &peer_a_keypair.public_key_source.get_key_path(),
        None,
        true,
    )?;
    rosenpass::cli::run::generate_and_save_keypair(
        None,
        &peer_b_keypair.secret_key_source.get_key_path(),
        &peer_b_keypair.public_key_source.get_key_path(),
        None,
        true,
    )?;

    // Start the peers, each in their own thread
    let (terminate_peer_a, peer_a_termination_handler) = mpsc::channel();
    let (terminate_peer_b, peer_b_termination_handler) = mpsc::channel();
    let peer_a_thread = std::thread::spawn(move || {
        rosenpass::cli::run::exchange_implementation(
            &peer_a,
            None,
            test_helpers(peer_a_termination_handler),
        )
    });
    let peer_b_thread = std::thread::spawn(move || {
        rosenpass::cli::run::exchange_implementation(
            &peer_b,
            None,
            test_helpers(peer_b_termination_handler),
        )
    });

    // Wait for the keys to successfully exchange a key
    let mut attempt = 0;
    loop {
        // Both peers run in threads of this very process, so we can not read their stdout
        // to learn when the keys have been written; instead, wait for the keys to show up
        // in the output key files.
        let osk_a = wait_for_osk(&peer_a_osk)?;
        let osk_b = wait_for_osk(&peer_b_osk)?;

        match osk_a.secret() == osk_b.secret() {
            true => break,
            false if attempt > 10 => bail!(
                "Peers did not produce a matching key even after ten attempts. Something is wrong with the key exchange!"
            ),
            false => {
                attempt += 1;
                sleep(Duration::from_millis(200));
            }
        };
    }

    // Now connect to the peers
    let api_a = UnixStream::connect(&peer_a_api_path)?;
    let api_b = UnixStream::connect(&peer_b_api_path)?;

    for conn in ([api_a, api_b]).iter() {
        let mut echo = [0u8; 256];
        copy_slice_least_src("Hello World".as_bytes()).to(&mut echo);

        let req = api::PingRequest::new(echo);
        LengthPrefixEncoder::from_message(req.as_bytes()).write_all_to_stdio(conn)?;

        let mut decoder = LengthPrefixDecoder::new([0u8; api::MAX_RESPONSE_LEN]);
        let res = decoder.read_all_from_stdio(conn)?;
        let res = res.zk_parse::<api::PingResponse>()?;
        assert_eq!(*res, api::PingResponse::new(echo));
    }

    // Stop the peers
    terminate_peer_a.send(())?;
    terminate_peer_b.send(())?;
    peer_a_thread
        .join()
        .map_err(|_| anyhow::anyhow!("peer a thread panicked"))??;
    peer_b_thread
        .join()
        .map_err(|_| anyhow::anyhow!("peer b thread panicked"))??;

    Ok(())
}
