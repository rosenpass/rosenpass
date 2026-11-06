//! TODO: write documentation
//! https://github.com/rosenpass/rosenpass/issues/1172
//!
//!
//! This integration test uses the wireguard extension.
//! See the whitepaper section 3.2 for more information.
//! https://rosenpass.eu/docs/whitepaper

use std::{
    borrow::Borrow, io::Write, os::unix::net::UnixStream, sync::mpsc, thread::sleep, time::Duration,
};

use anyhow::bail;
use hex_literal::hex;
use rosenpass::app_server::AppServerTest;
use rosenpass::config::{
    KeyFromDiskOrB64EncodedStringInner, ProtocolVersion, PublicKeySource, PublicPqKeySource,
};
use rosenpass::internal::util::{
    b64::B64Display,
    file::LoadValueB64,
    io::IoErrorKind,
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
    mio::WriteWithFileDescriptors,
    zerocopy::ZerocopySliceExt,
};
use rosenpass::protocol::basic_types::SymKey;
use rosenpass::{
    api::{
        self, add_listen_socket_response_status, add_psk_broker_response_status,
        supply_keypair_response_status,
    },
    config::{KeyFromDiskInner, NewFromInner, PqKeypairSource, SecretPqKeySource},
};
use std::os::fd::{AsFd, IntoRawFd};
use tempfile::TempDir;
use zerocopy::IntoBytes;

fn test_helpers(termination_handler: mpsc::Receiver<()>) -> Option<AppServerTest> {
    Some(AppServerTest {
        enable_dos_permanently: false,
        termination_handler: Some(termination_handler),
        skip_init_logging: true,
    })
}

#[test]
fn api_integration_api_setup_v02() -> anyhow::Result<()> {
    api_integration_api_setup(ProtocolVersion::V02)
}

#[test]
fn api_integration_api_setup_v03() -> anyhow::Result<()> {
    api_integration_api_setup(ProtocolVersion::V03)
}

/// see module documentation
fn api_integration_api_setup(protocol_version: ProtocolVersion) -> anyhow::Result<()> {
    let dir = TempDir::with_prefix("rosenpass-api-integration-test")?;

    macro_rules! tempfile {
        ($($lst:expr),+) => {{
            let mut buf =  dir.path().to_path_buf();
            $(buf.push($lst);)*
            buf
        }}
    }

    // peer a config
    let peer_a_endpoint = "[::1]:0";
    let peer_a_listen = std::net::UdpSocket::bind(peer_a_endpoint)?;
    let peer_a_endpoint = format!("{}", peer_a_listen.local_addr()?);
    let peer_a_keypair = PqKeypairSource {
        secret_key_source: SecretPqKeySource::new(KeyFromDiskInner::File(tempfile!("a.sk"))),
        public_key_source: PublicPqKeySource::new(KeyFromDiskInner::File(tempfile!("a.pk"))),
    };

    // peer a's own WireGuard public key, required since protocol version 3
    let peer_a_wg_peer_id = hex!(
        "
        60 4b 1c f1 a2 48 a0 77  03 3c e8 54 95 f4 30 4c
        24 3d 5e a8 20 6d 4b 74  77 9f 4a 27 e6 37 61 89
    "
    );

    // peer b config
    let peer_b_osk = tempfile!("b.osk");
    let peer_b_wg_device = "mock_device";
    let peer_b_wg_peer_id = hex!(
        "
        93 0f ee 77 0c 6b 54 7e  13 5f 13 92 21 97 26 53
        7d 77 4a 6a 0f 6c eb 1a  dd 6e 5b c4 1b 92 cd 99
    "
    );

    // whether or not to pass the wireguard pubkeys, required since protocol version 3
    let use_wg_key_binding = match protocol_version {
        ProtocolVersion::V02 => false,
        ProtocolVersion::V03 => true,
    };

    // an API connection handed to peer a which will be fed invalid data later; checks that the API
    // connections are closed when invalid data is received
    let (deliberate_fail_api_client, deliberate_fail_api_server) =
        std::os::unix::net::UnixStream::pair()?;

    use rosenpass::config;
    let peer_a_api_path = tempfile!("a.sock");
    // peer a is supplied with its own keypair and its listen socket via the API later
    let mut peer_a = config::RosenpassConfig::new_minimal(None, None);
    peer_a.api.listen_path = vec![peer_a_api_path.clone()];
    peer_a.api.stream_fd = vec![deliberate_fail_api_server.into_raw_fd()];
    peer_a.verbosity = config::Verbosity::Verbose;
    peer_a.supported_protocol_versions.clear();
    peer_a.supported_protocol_versions.insert(protocol_version);
    peer_a.peers.push(config::PeerConfig {
        name: "a".to_string(),
        enabled: true,
        their_public_key: PublicPqKeySource::new(KeyFromDiskInner::File(tempfile!("b.pk"))),
        endpoint: None,
        preshared_key: None,
        osk_domain_separator: Default::default(),
        output_to_file: None,
        wireguard: Some(config::WireguardConfig {
            enabled: true,
            device_name: peer_b_wg_device.to_string(),
            our_wireguard_keypair: use_wg_key_binding.then(|| {
                config::OurWireguardKeypair::PublicKeyOnly(
                    config::KeyFromDiskOrB64EncodedString::new(
                        config::KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(format!(
                            "{}",
                            peer_a_wg_peer_id.fmt_b64::<8129>()
                        )),
                    ),
                )
            }),
            // TODO:
            // 1. why 8129? That magic number needs explanation.
            // 2. Was this supposed to be 8192? In that case, please correct.
            // 3. In any case, it is way too long and could be much shorter(?)
            // 4. Also fix another occurence further below.
            their_wireguard_public_key: config::PublicWgKeySource::new(
                KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(format!(
                    "{}",
                    peer_b_wg_peer_id.fmt_b64::<8129>()
                )),
            ),
            wireguard_options: Default::default(),
            exchange_command: None,
            osk_domain_separator: Default::default(),
        }),
    });

    let peer_b_keypair = PqKeypairSource {
        secret_key_source: SecretPqKeySource::new(KeyFromDiskInner::File(tempfile!("b.sk"))),
        public_key_source: PublicPqKeySource::new(KeyFromDiskInner::File(tempfile!("b.pk"))),
    };
    let mut peer_b = config::RosenpassConfig::new_minimal(
        Some(peer_b_keypair.secret_key_source.get_key_path()),
        Some(peer_b_keypair.public_key_source.get_key_path()),
    );
    peer_b.api.listen_path = vec![tempfile!("b.sock")];
    peer_b.verbosity = config::Verbosity::Verbose;
    peer_b.supported_protocol_versions.clear();
    peer_b.supported_protocol_versions.insert(protocol_version);
    peer_b.peers.push(config::PeerConfig {
        name: "b".to_string(),
        enabled: true,
        their_public_key: PublicPqKeySource::new(KeyFromDiskInner::File(tempfile!("a.pk"))),
        endpoint: Some(peer_a_endpoint.to_owned()),
        preshared_key: None,
        osk_domain_separator: Default::default(),
        output_to_file: Some(config::OutputToFileConfig {
            enabled: true,
            output_file_path: peer_b_osk.clone(),
            osk_domain_separator: Default::default(),
        }),
        // This was `wg: None` previously, introduced in a huge commit b1a7d942954ce6a41decc5a9f93c95cffafde801 .
        // We need to clean up and document this test.
        // https://github.com/rosenpass/rosenpass/issues/1172
        wireguard: Some(config::WireguardConfig {
            enabled: true,
            device_name: peer_b_wg_device.to_string(),
            our_wireguard_keypair: use_wg_key_binding.then(|| {
                config::OurWireguardKeypair::PublicKeyOnly(
                    config::KeyFromDiskOrB64EncodedString::new(
                        config::KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(format!(
                            "{}",
                            peer_b_wg_peer_id.fmt_b64::<8129>()
                        )),
                    ),
                )
            }),
            // TODO:
            // 1. why 8129? That magic number needs explanation.
            // 2. Was this supposed to be 8192? In that case, please correct.
            // 3. In any case, it is way too long and could be much shorter(?)
            // 4. Also fix another occurence further below.
            their_wireguard_public_key: config::PublicWgKeySource::new(
                KeyFromDiskOrB64EncodedStringInner::Base64EncodedString(format!(
                    "{}",
                    peer_a_wg_peer_id.fmt_b64::<8129>()
                )),
            ),
            wireguard_options: Default::default(),
            exchange_command: None,
            osk_domain_separator: Default::default(),
        }),
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

    // Now connect to the peers
    let api_path = peer_a_api_path.as_path();

    // Wait for the socket to be created
    let mut attempt = 0;
    while !api_path.exists() {
        sleep(Duration::from_millis(1000));
        attempt += 1;
        assert!(
            attempt < 50,
            "Api failed to be created even after 50 seconds"
        );
    }

    let api = UnixStream::connect(api_path)?;
    let (psk_broker_sock, psk_broker_server_sock) = UnixStream::pair()?;

    // Send AddListenSocket request
    {
        let fd = peer_a_listen.as_fd();

        let mut fds = vec![&fd].into();
        let mut api = WriteWithFileDescriptors::<UnixStream, _, _, _>::new(&api, &mut fds);
        LengthPrefixEncoder::from_message(api::AddListenSocketRequest::new().as_bytes())
            .write_all_to_stdio(&mut api)?;
        assert!(fds.is_empty(), "Failed to write all file descriptors");
        std::mem::forget(peer_a_listen);
    }

    // Read response
    {
        let mut decoder = LengthPrefixDecoder::new([0u8; api::MAX_RESPONSE_LEN]);
        let res = decoder.read_all_from_stdio(&api)?;
        let res = res.zk_parse::<api::AddListenSocketResponse>()?;
        assert_eq!(
            *res,
            api::AddListenSocketResponse::new(add_listen_socket_response_status::OK)
        );
    }

    // Deliberately break API connection given via FD; this checks that the
    // API connections are closed when invalid data is received and it also
    // implicitly checks that other connections are unaffected
    {
        use std::io::ErrorKind as K;
        let client = deliberate_fail_api_client;
        let err = loop {
            if let Err(e) = client.borrow().write(&[0xffu8; 16]) {
                break e;
            }
        };
        // NotConnected happens on Mac
        assert!(matches!(
            err.io_error_kind(),
            K::ConnectionReset | K::BrokenPipe | K::NotConnected
        ));
    }

    // Send `AddPskBrokerRequest`
    //
    // This must happen before `SupplyKeypair`: without a keypair, peer a
    // cannot complete any key exchange, so the broker is guaranteed to be
    // replaced before the first SetPsk message is sent through it. Otherwise
    // an exchange that completes early would deliver the first key through
    // the startup (native unix) broker and it would be lost to this test.
    {
        let mut fds = vec![psk_broker_server_sock.as_fd()].into();
        let mut api = WriteWithFileDescriptors::<UnixStream, _, _, _>::new(&api, &mut fds);
        LengthPrefixEncoder::from_message(api::AddPskBrokerRequest::new().as_bytes())
            .write_all_to_stdio(&mut api)?;
        assert!(fds.is_empty(), "Failed to write all file descriptors");
    }

    // Read response
    {
        let mut decoder = LengthPrefixDecoder::new([0u8; api::MAX_RESPONSE_LEN]);
        let res = decoder.read_all_from_stdio(&api)?;
        let res = res.zk_parse::<api::AddPskBrokerResponse>()?;
        assert_eq!(
            *res,
            api::AddPskBrokerResponse::new(add_psk_broker_response_status::OK)
        );
    }

    // Send `SupplyKeyPairRequest`
    {
        use rustix::fs::{Mode, OFlags, open};
        let sk = open(
            peer_a_keypair.secret_key_source.get_key_path(),
            OFlags::RDONLY,
            Mode::empty(),
        )?;
        let pk = open(
            peer_a_keypair.public_key_source.get_key_path(),
            OFlags::RDONLY,
            Mode::empty(),
        )?;

        let mut fds = vec![&sk, &pk].into();

        let mut api = WriteWithFileDescriptors::<UnixStream, _, _, _>::new(&api, &mut fds);
        LengthPrefixEncoder::from_message(api::SupplyKeypairRequest::new().as_bytes())
            .write_all_to_stdio(&mut api)?;
        assert!(fds.is_empty(), "Failed to write all file descriptors");
    }

    // Read response
    {
        let mut decoder = LengthPrefixDecoder::new([0u8; api::MAX_RESPONSE_LEN]);
        let res = decoder.read_all_from_stdio(&api)?;
        let res = res.zk_parse::<api::SupplyKeypairResponse>()?;
        assert_eq!(
            *res,
            api::SupplyKeypairResponse::new(supply_keypair_response_status::OK)
        );
    }

    // Wait for the keys to successfully exchange a key
    let mut attempt = 0;
    loop {
        // Read OSK generated by A
        let osk_a = {
            use rosenpass::internal::wireguard_broker::api::msgs as M;
            type SetPskReqPkg = M::Envelope<M::SetPskRequest>;
            type SetPskResPkg = M::Envelope<M::SetPskResponse>;

            // Receive request
            let mut decoder = LengthPrefixDecoder::new([0u8; M::REQUEST_MSG_BUFFER_SIZE]);
            let req = decoder.read_all_from_stdio(&psk_broker_sock)?;

            let req = req.zk_parse::<SetPskReqPkg>()?;
            assert_eq!(req.msg_type, M::MsgType::SetPsk as u8);
            assert_eq!(req.payload.peer_id, peer_b_wg_peer_id);
            assert_eq!(req.payload.iface()?, peer_b_wg_device);

            // Send response
            let res = SetPskResPkg {
                msg_type: M::MsgType::SetPsk as u8,
                reserved: [0u8; 3],
                payload: M::SetPskResponse {
                    return_code: M::SetPskResponseReturnCode::Success as u8,
                },
            };
            LengthPrefixEncoder::from_message(res.as_bytes())
                .write_all_to_stdio(&psk_broker_sock)?;

            SymKey::from_slice(&req.payload.psk)
        };

        // Read OSK generated by B
        let osk_b = {
            let mut attempt = 0;
            loop {
                match SymKey::load_b64::<64, _>(&peer_b_osk) {
                    Ok(osk) => break osk,
                    Err(err) => {
                        attempt += 1;
                        assert!(
                            attempt < 50,
                            "Peer b did not write its output key to {peer_b_osk:?}: {err}"
                        );
                        sleep(Duration::from_millis(200));
                    }
                }
            }
        };

        // TODO: This may be flaky. Both rosenpass instances are not guaranteed to produce
        // the same number of output events; they merely guarantee eventual consistency of OSK.
        // Correctly, we should use tokio to read any number of generated OSKs and indicate
        // success on consensus
        match osk_a.secret() == osk_b.secret() {
            true => break,
            false if attempt > 10 => bail!(
                "Peers did not produce a matching key even after ten attempts. Something is wrong with the key exchange!"
            ),
            false => {}
        };

        attempt += 1;
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
