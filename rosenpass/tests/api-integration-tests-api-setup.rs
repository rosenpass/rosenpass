use std::{
    borrow::Borrow,
    io::{BufRead, BufReader, Write},
    os::unix::net::UnixStream,
    process::Stdio,
    thread::sleep,
    time::Duration,
};

use anyhow::{bail, Context};
use command_fds::{CommandFdExt, FdMapping};
use hex_literal::hex;
use rosenpass::api::{
    self, add_listen_socket_response_status, add_psk_broker_response_status,
    supply_keypair_response_status,
};
use rosenpass_util::{
    b64::B64Display,
    file::LoadValueB64,
    io::IoErrorKind,
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
    mem::{DiscardResultExt, MoveExt},
    mio::WriteWithFileDescriptors,
    zerocopy::ZerocopySliceExt,
};
use std::os::fd::{AsFd, AsRawFd};
use tempfile::TempDir;
use zerocopy::AsBytes;

use rosenpass::protocol::SymKey;

struct KillChild(std::process::Child);

impl Drop for KillChild {
    fn drop(&mut self) {
        self.0.kill().discard_result();
        self.0.wait().discard_result()
    }
}

#[test]
fn api_integration_api_setup() -> anyhow::Result<()> {
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

    let dir = TempDir::with_prefix("rosenpass-api-integration-test")?;

    macro_rules! tempfile {
        ($($lst:expr),+) => {{
            let mut buf =  dir.path().to_path_buf();
            $(buf.push($lst);)*
            buf
        }}
    }

    let peer_a_endpoint = "[::1]:0";
    let peer_a_listen = std::net::UdpSocket::bind(peer_a_endpoint)?;
    let peer_a_endpoint = format!("{}", peer_a_listen.local_addr()?);
    let peer_a_keypair = config::Keypair::new(tempfile!("a.pk"), tempfile!("a.sk"));

    let peer_b_osk = tempfile!("b.osk");
    let peer_b_wg_device = "mock_device";
    let peer_b_wg_peer_id = hex!(
        "
        93 0f ee 77 0c 6b 54 7e  13 5f 13 92 21 97 26 53
        7d 77 4a 6a 0f 6c eb 1a  dd 6e 5b c4 1b 92 cd 99
    "
    );

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
                peer: format!("{}", peer_b_wg_peer_id.fmt_b64::<8129>()),
                extra_params: vec![],
            }),
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
            wg: None,
        }],
    };

    // Generate the keys
    rosenpass::cli::testing::generate_and_save_keypair(
        peer_a_keypair.secret_key.clone(),
        peer_a_keypair.public_key.clone(),
    )?;
    rosenpass::cli::testing::generate_and_save_keypair(
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
                parent_fd: deliberate_fail_api_server.move_here().as_raw_fd(),
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
            .stderr(Stdio::null())
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

    // Send SupplyKeypairRequest
    {
        use rustix::fs::{open, Mode, OFlags};
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

    // Send AddPskBroker request
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

    // Wait for the keys to successfully exchange a key
    let mut attempt = 0;
    loop {
        // Read OSK generated by A
        let osk_a = {
            use rosenpass_wireguard_broker::api::msgs as M;
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
            false if attempt > 10 => bail!("Peers did not produce a matching key even after ten attempts. Something is wrong with the key exchange!"),
            false => {},
        };

        attempt += 1;
    }

    Ok(())
}
