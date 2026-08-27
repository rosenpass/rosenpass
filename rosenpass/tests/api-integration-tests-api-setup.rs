//! TODO: write documentation
//! https://github.com/rosenpass/rosenpass/issues/1172
//!
//!
//! This integration test uses the wireguard extension.
//! See the whitepaper section 3.2 for more information.
//! https://rosenpass.eu/docs/whitepaper

use std::{
    borrow::Borrow,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::Stdio,
    thread::sleep,
    time::Duration,
};

use anyhow::{Context, bail};
use command_fds::{CommandFdExt, FdMapping};
use hex_literal::hex;
use rosenpass::api::{
    self, add_listen_socket_response_status, add_psk_broker_response_status,
    supply_keypair_response_status,
};
use rosenpass::config::ProtocolVersion;
use rosenpass::internal::util::{
    b64::B64Display,
    file::LoadValueB64,
    io::IoErrorKind,
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
    mem::{DiscardResultExt, MoveExt},
    mio::WriteWithFileDescriptors,
    zerocopy::ZerocopySliceExt,
};
use rosenpass::protocol::basic_types::SymKey;
use std::os::fd::AsFd;
use tempfile::TempDir;
use zerocopy::IntoBytes;

struct KillChild(std::process::Child);

impl Drop for KillChild {
    fn drop(&mut self) {
        const TERM: rustix::process::Signal = rustix::process::Signal::TERM;
        use rustix::process::{Pid, kill_process};
        let pid = Pid::from_child(&self.0);
        // We seriously need to start handling signals with signalfd, our current signal handling
        // system is a bit broken; there is probably a few functions that just restart on EINTR
        // so the signal is absorbed
        loop {
            kill_process(pid, TERM).discard_result();
            if self.0.try_wait().unwrap().is_some() {
                break;
            }
        }
    }
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
    rosenpass::internal::secret_memory::policy::secret_policy_use_only_malloc_secrets();

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
    let peer_a_keypair = config::Keypair::new(tempfile!("a.pk"), tempfile!("a.sk"));
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

    use rosenpass::config;
    let peer_a = config::Rosenpass {
        config_file_path: tempfile!("a.config"),
        keypair: None,
        listen: vec![], // TODO: This could collide by accident
        verbosity: config::Verbosity::Verbose,
        api: api::config::ApiConfig {
            listen_path: vec![tempfile!("a.sock")],
            listen_fd: vec![],
            stream_fd: vec![],
        },
        peers: vec![config::RosenpassPeer {
            public_key: tempfile!("b.pk"),
            key_out: None,
            endpoint: None,
            pre_shared_key: None,
            wg: Some(config::WireGuard {
                device: peer_b_wg_device.to_string(),
                // TODO:
                // 1. why 8129? That magic number needs explanation.
                // 2. Was this supposed to be 8192? In that case, please correct.
                // 3. In any case, it is way too long and could be much shorter(?)
                // 4. Also fix another occurence further below.
                peer: format!("{}", peer_b_wg_peer_id.fmt_b64::<8129>()),
                our_wg_pubkey: use_wg_key_binding
                    .then(|| format!("{}", peer_a_wg_peer_id.fmt_b64::<8129>())),
                extra_params: vec![],
            }),
            protocol_version,
            osk_domain_separator: Default::default(),
        }],
    };

    let peer_b_keypair = config::Keypair::new(tempfile!("b.pk"), tempfile!("b.sk"));
    let peer_b = config::Rosenpass {
        config_file_path: tempfile!("b.config"),
        keypair: Some(peer_b_keypair.clone()),
        listen: vec![],
        verbosity: config::Verbosity::Verbose,
        api: api::config::ApiConfig {
            listen_path: vec![tempfile!("b.sock")],
            listen_fd: vec![],
            stream_fd: vec![],
        },
        peers: vec![config::RosenpassPeer {
            public_key: tempfile!("a.pk"),
            key_out: Some(peer_b_osk.clone()),
            endpoint: Some(peer_a_endpoint.to_owned()),
            pre_shared_key: None,
            // This was `wg: None` previously, introduced in a huge commit b1a7d942954ce6a41decc5a9f93c95cffafde801 .
            // We need to clean up and document this test.
            // https://github.com/rosenpass/rosenpass/issues/1172
            wg: use_wg_key_binding.then(|| config::WireGuard {
                device: peer_b_wg_device.to_string(),
                peer: format!("{}", peer_a_wg_peer_id.fmt_b64::<8129>()),
                our_wg_pubkey: Some(format!("{}", peer_b_wg_peer_id.fmt_b64::<8129>())),
                extra_params: vec![],
            }),
            protocol_version,
            osk_domain_separator: Default::default(),
        }],
    };

    // Generate the keys
    rosenpass::oldcli::testing::generate_and_save_keypair(
        peer_a_keypair.secret_key.clone(),
        peer_a_keypair.public_key.clone(),
    )?;
    rosenpass::oldcli::testing::generate_and_save_keypair(
        peer_b_keypair.secret_key.clone(),
        peer_b_keypair.public_key.clone(),
    )?;

    // Write the configuration files
    peer_a.commit()?;
    peer_b.commit()?;

    let (deliberate_fail_api_client, deliberate_fail_api_server) =
        std::os::unix::net::UnixStream::pair()?;
    let deliberate_fail_child_fd = 3;

    // Start peer a
    let _proc_a = KillChild(
        std::process::Command::new(env!("CARGO_BIN_EXE_rosenpass"))
            .args(["--api-stream-fd", &deliberate_fail_child_fd.to_string()])
            .fd_mappings(vec![FdMapping {
                parent_fd: deliberate_fail_api_server.move_here().into(),
                child_fd: 3,
            }])?
            .args([
                "exchange-config",
                peer_a.config_file_path.to_str().context("")?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .spawn()?,
    );

    // Start peer b
    let mut proc_b = KillChild(
        std::process::Command::new(env!("CARGO_BIN_EXE_rosenpass"))
            .args([
                "exchange-config",
                peer_b.config_file_path.to_str().context("")?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .spawn()?,
    );

    // Acquire stdout
    let mut out_b = BufReader::new(proc_b.0.stdout.take().context("")?).lines();

    // Now connect to the peers
    let api_path = peer_a.api.listen_path[0].as_path();

    // Wait for the socket to be created
    let attempt = 0;
    while !api_path.exists() {
        sleep(Duration::from_millis(200));
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
        let sk = open(peer_a_keypair.secret_key, OFlags::RDONLY, Mode::empty())?;
        let pk = open(peer_a_keypair.public_key, OFlags::RDONLY, Mode::empty())?;

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
            let line = out_b.next().context("")??;
            let words = line.split(' ').collect::<Vec<_>>();

            // FIXED     FIXED PEER-ID                                      FIXED    FILENAME       STATUS
            // output-key peer KZqXTZ4l2aNnkJtLPhs4D8JxHTGmRSL9w3Qr+X8JxFk= key-file "client-A-osk" exchanged
            let peer_id = words
                .get(2)
                .with_context(|| format!("Bad rosenpass output: `{line}`"))?;
            assert_eq!(
                line,
                format!(
                    "output-key peer {peer_id} key-file \"{}\" exchanged",
                    peer_b_osk.to_str().context("")?
                )
            );

            SymKey::load_b64::<64, _>(peer_b_osk.clone())?
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

    Ok(())
}
