use std::{
    io::{BufRead, BufReader},
    net::ToSocketAddrs,
    os::unix::net::UnixStream,
    process::Stdio,
};

use anyhow::{bail, Context};
use rosenpass::api;
use rosenpass_to::{ops::copy_slice_least_src, To};
use rosenpass_util::{
    file::LoadValueB64,
    length_prefix_encoding::{decoder::LengthPrefixDecoder, encoder::LengthPrefixEncoder},
};
use rosenpass_util::{mem::DiscardResultExt, zerocopy::ZerocopySliceExt};
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
fn api_integration_test() -> anyhow::Result<()> {
    rosenpass_secret_memory::policy::secret_policy_use_only_malloc_secrets();

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

    let peer_a_keypair = config::Keypair::new(tempfile!("a.pk"), tempfile!("a.sk"));
    let peer_a = config::Rosenpass {
        config_file_path: tempfile!("a.config"),
        keypair: Some(peer_a_keypair.clone()),
        listen: peer_a_endpoint.to_socket_addrs()?.collect(), // TODO: This could collide by accident
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
    let mut proc_a = KillChild(
        std::process::Command::new(env!("CARGO_BIN_EXE_rosenpass"))
            .args([
                "exchange-config",
                peer_a.config_file_path.to_str().context("")?,
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
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
    let mut out_a = BufReader::new(proc_a.0.stdout.take().context("")?).lines();
    let mut out_b = BufReader::new(proc_b.0.stdout.take().context("")?).lines();

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

    // Now connect to the peers
    let api_a = UnixStream::connect(&peer_a.api.listen_path[0])?;
    let api_b = UnixStream::connect(&peer_b.api.listen_path[0])?;

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

    Ok(())
}
