use std::{
    io::{BufRead, BufReader},
    os::unix::net::UnixStream,
    process::Stdio,
    thread::sleep,
    time::Duration,
};

use anyhow::{bail, Context};
use rosenpass::api::{self, add_listen_socket_response_status, supply_keypair_response_status};
use rosenpass_util::{
    file::LoadValueB64,
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
    mio::WriteWithFileDescriptors,
    zerocopy::ZerocopySliceExt,
};
use rustix::fd::AsFd;
use tempfile::TempDir;
use zerocopy::AsBytes;

use rosenpass::protocol::SymKey;

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
    let peer_a_osk = tempfile!("a.osk");
    let peer_b_osk = tempfile!("b.osk");

    let peer_a_listen = std::net::UdpSocket::bind(peer_a_endpoint)?;
    let peer_a_endpoint = format!("{}", peer_a_listen.local_addr()?);

    use rosenpass::config;

    let peer_a_keypair = config::Keypair::new(tempfile!("a.pk"), tempfile!("a.sk"));
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
            key_out: Some(peer_a_osk.clone()),
            endpoint: None,
            pre_shared_key: None,
            wg: None,
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

    // Start peer a
    let proc_a = std::process::Command::new(env!("CARGO_BIN_EXE_rosenpass"))
        .args([
            "exchange-config",
            peer_a.config_file_path.to_str().context("")?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    // Start peer b
    let proc_b = std::process::Command::new(env!("CARGO_BIN_EXE_rosenpass"))
        .args([
            "exchange-config",
            peer_b.config_file_path.to_str().context("")?,
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .spawn()?;

    // Acquire stdout
    let mut out_a = BufReader::new(proc_a.stdout.context("")?).lines();
    let mut out_b = BufReader::new(proc_b.stdout.context("")?).lines();

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
        let res = decoder.read_all_from_stdio(api)?;
        let res = res.zk_parse::<api::SupplyKeypairResponse>()?;
        assert_eq!(
            *res,
            api::SupplyKeypairResponse::new(supply_keypair_response_status::OK)
        );
    }

    // Wait for the keys to successfully exchange a key
    let mut attempt = 0;
    loop {
        let line_a = out_a.next().context("")??;
        let line_b = out_b.next().context("")??;

        let words_a = line_a.split(' ').collect::<Vec<_>>();
        let words_b = line_b.split(' ').collect::<Vec<_>>();

        // FIXED     FIXED PEER-ID                                      FIXED    FILENAME       STATUS
        // output-key peer KZqXTZ4l2aNnkJtLPhs4D8JxHTGmRSL9w3Qr+X8JxFk= key-file "client-A-osk" exchanged
        let peer_a_id = words_b
            .get(2)
            .with_context(|| format!("Bad rosenpass output: `{line_b}`"))?;
        let peer_b_id = words_a
            .get(2)
            .with_context(|| format!("Bad rosenpass output: `{line_a}`"))?;
        assert_eq!(
            line_a,
            format!(
                "output-key peer {peer_b_id} key-file \"{}\" exchanged",
                peer_a_osk.to_str().context("")?
            )
        );
        assert_eq!(
            line_b,
            format!(
                "output-key peer {peer_a_id} key-file \"{}\" exchanged",
                peer_b_osk.to_str().context("")?
            )
        );

        // Read OSKs
        let osk_a = SymKey::load_b64::<64, _>(peer_a_osk.clone())?;
        let osk_b = SymKey::load_b64::<64, _>(peer_b_osk.clone())?;
        match osk_a.secret() == osk_b.secret() {
            true => break,
            false if attempt > 10 => bail!("Peers did not produce a matching key even after ten attempts. Something is wrong with the key exchange!"),
            false => {},
        };

        attempt += 1;
    }

    Ok(())
}
