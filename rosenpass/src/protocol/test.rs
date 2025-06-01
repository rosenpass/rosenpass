use std::{borrow::BorrowMut, fmt::Display, net::SocketAddrV4, ops::DerefMut};

use anyhow::{Context, Result};
use serial_test::serial;
use zerocopy::{AsBytes, FromBytes, FromZeroes};

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use rosenpass_secret_memory::Public;
use rosenpass_util::mem::DiscardResultExt;

use crate::{
    msgs::{EmptyData, Envelope, InitConf, InitHello, MsgType, RespHello, MAX_MESSAGE_LEN},
    protocol::{basic_types::MsgBuf, constants::REKEY_AFTER_TIME_RESPONDER},
};

use super::{
    basic_types::{SPk, SSk, SymKey},
    *,
};

struct VecHostIdentifier(Vec<u8>);

impl HostIdentification for VecHostIdentifier {
    fn encode(&self) -> &[u8] {
        &self.0
    }
}

impl Display for VecHostIdentifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.0)
    }
}

impl From<Vec<u8>> for VecHostIdentifier {
    fn from(v: Vec<u8>) -> Self {
        VecHostIdentifier(v)
    }
}

fn setup_logging() {
    use std::io::Write;
    let mut log_builder = env_logger::Builder::from_default_env(); // sets log level filter from environment (or defaults)
    log_builder.filter_level(log::LevelFilter::Info);
    log_builder.format_timestamp_nanos();
    log_builder.format(|buf, record| {
        let ts_format = buf.timestamp_nanos().to_string();
        writeln!(buf, "{}: {}", &ts_format[14..], record.args())
    });

    let _ = log_builder.try_init();
}

#[test]
#[serial]
fn handles_incorrect_size_messages_v02() {
    handles_incorrect_size_messages(ProtocolVersion::V02)
}

#[test]
#[serial]
fn handles_incorrect_size_messages_v03() {
    handles_incorrect_size_messages(ProtocolVersion::V03)
}

/// Ensure that the protocol implementation can deal with truncated
/// messages and with overlong messages.
///
/// This test performs a complete handshake between two randomly generated
/// servers; instead of delivering the message correctly at first messages
/// of length zero through about 1.2 times the correct message size are delivered.
///
/// Producing an error is expected on each of these messages.
///
/// Finally the correct message is delivered and the same process
/// starts again in the other direction.
///
/// Through all this, the handshake should still successfully terminate;
/// i.e. an exchanged key must be produced in both servers.
fn handles_incorrect_size_messages(protocol_version: ProtocolVersion) {
    setup_logging();
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    stacker::grow(8 * 1024 * 1024, || {
        const OVERSIZED_MESSAGE: usize = ((MAX_MESSAGE_LEN as f32) * 1.2) as usize;
        type MsgBufPlus = Public<OVERSIZED_MESSAGE>;

        const PEER0: PeerPtr = PeerPtr(0);

        let (mut me, mut they) = make_server_pair(protocol_version).unwrap();
        let (mut msgbuf, mut resbuf) = (MsgBufPlus::zero(), MsgBufPlus::zero());

        // Process the entire handshake
        let mut msglen = Some(me.initiate_handshake(PEER0, &mut *resbuf).unwrap());
        while let Some(l) = msglen {
            std::mem::swap(&mut me, &mut they);
            std::mem::swap(&mut msgbuf, &mut resbuf);
            msglen = test_incorrect_sizes_for_msg(&mut me, &*msgbuf, l, &mut *resbuf);
        }

        assert_eq!(
            me.osk(PEER0).unwrap().secret(),
            they.osk(PEER0).unwrap().secret()
        );
    });
}

/// Used in handles_incorrect_size_messages() to first deliver many truncated
/// and overlong messages, finally the correct message is delivered and the response
/// returned.
fn test_incorrect_sizes_for_msg(
    srv: &mut CryptoServer,
    msgbuf: &[u8],
    msglen: usize,
    resbuf: &mut [u8],
) -> Option<usize> {
    resbuf.fill(0);

    for l in 0..(((msglen as f32) * 1.2) as usize) {
        if l == msglen {
            continue;
        }

        let res = srv.handle_msg(&msgbuf[..l], resbuf);
        assert!(res.is_err()); // handle_msg should raise an error
        assert!(!resbuf.iter().any(|x| *x != 0)); // resbuf should not have been changed
    }

    // Apply the proper handle_msg operation
    srv.handle_msg(&msgbuf[..msglen], resbuf).unwrap().resp
}

fn keygen() -> Result<(SSk, SPk)> {
    // TODO: Copied from the benchmark; deduplicate
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem.keygen(sk.secret_mut(), pk.deref_mut())?;
    Ok((sk, pk))
}

fn make_server_pair(protocol_version: ProtocolVersion) -> Result<(CryptoServer, CryptoServer)> {
    // TODO: Copied from the benchmark; deduplicate
    let psk = SymKey::random();
    let ((ska, pka), (skb, pkb)) = (keygen()?, keygen()?);
    let (mut a, mut b) = (
        CryptoServer::new(ska, pka.clone()),
        CryptoServer::new(skb, pkb.clone()),
    );
    a.add_peer(Some(psk.clone()), pkb, protocol_version.clone())?;
    b.add_peer(Some(psk), pka, protocol_version)?;
    Ok((a, b))
}

#[test]
#[serial]
fn test_regular_exchange_v02() {
    test_regular_exchange(ProtocolVersion::V02)
}

#[test]
#[serial]
fn test_regular_exchange_v03() {
    test_regular_exchange(ProtocolVersion::V03)
}

fn test_regular_exchange(protocol_version: ProtocolVersion) {
    setup_logging();
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    stacker::grow(8 * 1024 * 1024, || {
        type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
        let (mut a, mut b) = make_server_pair(protocol_version).unwrap();

        let mut a_to_b_buf = MsgBufPlus::zero();
        let mut b_to_a_buf = MsgBufPlus::zero();

        let ip_a: SocketAddrV4 = "127.0.0.1:8080".parse().unwrap();
        let mut ip_addr_port_a = ip_a.ip().octets().to_vec();
        ip_addr_port_a.extend_from_slice(&ip_a.port().to_be_bytes());

        let _ip_b: SocketAddrV4 = "127.0.0.1:8081".parse().unwrap();

        let init_hello_len = a.initiate_handshake(PeerPtr(0), &mut *a_to_b_buf).unwrap();

        let init_msg_type: MsgType = a_to_b_buf.value[0].try_into().unwrap();
        assert_eq!(init_msg_type, MsgType::InitHello);

        //B handles InitHello, sends RespHello
        let HandleMsgResult { resp, .. } = b
            .handle_msg(&a_to_b_buf.as_slice()[..init_hello_len], &mut *b_to_a_buf)
            .unwrap();

        let resp_hello_len = resp.unwrap();

        let resp_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();
        assert_eq!(resp_msg_type, MsgType::RespHello);

        let HandleMsgResult {
            resp,
            exchanged_with,
        } = a
            .handle_msg(&b_to_a_buf[..resp_hello_len], &mut *a_to_b_buf)
            .unwrap();

        let init_conf_len = resp.unwrap();
        let init_conf_msg_type: MsgType = a_to_b_buf.value[0].try_into().unwrap();

        assert_eq!(exchanged_with, Some(PeerPtr(0)));
        assert_eq!(init_conf_msg_type, MsgType::InitConf);

        //B handles InitConf, sends EmptyData
        let HandleMsgResult {
            resp: _,
            exchanged_with,
        } = b
            .handle_msg(&a_to_b_buf.as_slice()[..init_conf_len], &mut *b_to_a_buf)
            .unwrap();

        let empty_data_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();

        assert_eq!(exchanged_with, Some(PeerPtr(0)));
        assert_eq!(empty_data_msg_type, MsgType::EmptyData);
    });
}

#[test]
#[serial]
fn test_regular_init_conf_retransmit_v02() {
    test_regular_init_conf_retransmit(ProtocolVersion::V02)
}

#[test]
#[serial]
fn test_regular_init_conf_retransmit_v03() {
    test_regular_init_conf_retransmit(ProtocolVersion::V03)
}

fn test_regular_init_conf_retransmit(protocol_version: ProtocolVersion) {
    setup_logging();
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    stacker::grow(8 * 1024 * 1024, || {
        type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
        let (mut a, mut b) = make_server_pair(protocol_version).unwrap();

        let mut a_to_b_buf = MsgBufPlus::zero();
        let mut b_to_a_buf = MsgBufPlus::zero();

        let ip_a: SocketAddrV4 = "127.0.0.1:8080".parse().unwrap();
        let mut ip_addr_port_a = ip_a.ip().octets().to_vec();
        ip_addr_port_a.extend_from_slice(&ip_a.port().to_be_bytes());

        let _ip_b: SocketAddrV4 = "127.0.0.1:8081".parse().unwrap();

        let init_hello_len = a.initiate_handshake(PeerPtr(0), &mut *a_to_b_buf).unwrap();

        let init_msg_type: MsgType = a_to_b_buf.value[0].try_into().unwrap();
        assert_eq!(init_msg_type, MsgType::InitHello);

        //B handles InitHello, sends RespHello
        let HandleMsgResult { resp, .. } = b
            .handle_msg(&a_to_b_buf.as_slice()[..init_hello_len], &mut *b_to_a_buf)
            .unwrap();

        let resp_hello_len = resp.unwrap();

        let resp_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();
        assert_eq!(resp_msg_type, MsgType::RespHello);

        //A handles RespHello, sends InitConf, exchanges keys
        let HandleMsgResult {
            resp,
            exchanged_with,
        } = a
            .handle_msg(&b_to_a_buf[..resp_hello_len], &mut *a_to_b_buf)
            .unwrap();

        let init_conf_len = resp.unwrap();
        let init_conf_msg_type: MsgType = a_to_b_buf.value[0].try_into().unwrap();

        assert_eq!(exchanged_with, Some(PeerPtr(0)));
        assert_eq!(init_conf_msg_type, MsgType::InitConf);

        //B handles InitConf, sends EmptyData
        let HandleMsgResult {
            resp: _,
            exchanged_with,
        } = b
            .handle_msg(&a_to_b_buf.as_slice()[..init_conf_len], &mut *b_to_a_buf)
            .unwrap();

        let empty_data_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();

        assert_eq!(exchanged_with, Some(PeerPtr(0)));
        assert_eq!(empty_data_msg_type, MsgType::EmptyData);

        //B handles InitConf again, sends EmptyData
        let HandleMsgResult {
            resp: _,
            exchanged_with,
        } = b
            .handle_msg(&a_to_b_buf.as_slice()[..init_conf_len], &mut *b_to_a_buf)
            .unwrap();

        let empty_data_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();

        assert!(exchanged_with.is_none());
        assert_eq!(empty_data_msg_type, MsgType::EmptyData);
    });
}

#[test]
#[serial]
#[cfg(feature = "experiment_cookie_dos_mitigation")]
fn cookie_reply_mechanism_responder_under_load_v02() {
    cookie_reply_mechanism_initiator_bails_on_message_under_load(ProtocolVersion::V02)
}

#[test]
#[serial]
#[cfg(feature = "experiment_cookie_dos_mitigation")]
fn cookie_reply_mechanism_responder_under_load_v03() {
    cookie_reply_mechanism_initiator_bails_on_message_under_load(ProtocolVersion::V03)
}

#[cfg(feature = "experiment_cookie_dos_mitigation")]
fn cookie_reply_mechanism_responder_under_load(protocol_version: ProtocolVersion) {
    use std::time::Duration;

    setup_logging();
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    stacker::grow(8 * 1024 * 1024, || {
        type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
        let (mut a, mut b) = make_server_pair(protocol_version.clone()).unwrap();

        let mut a_to_b_buf = MsgBufPlus::zero();
        let mut b_to_a_buf = MsgBufPlus::zero();

        let ip_a: SocketAddrV4 = "127.0.0.1:8080".parse().unwrap();
        let mut ip_addr_port_a = ip_a.ip().octets().to_vec();
        ip_addr_port_a.extend_from_slice(&ip_a.port().to_be_bytes());

        let _ip_b: SocketAddrV4 = "127.0.0.1:8081".parse().unwrap();

        let init_hello_len = a.initiate_handshake(PeerPtr(0), &mut *a_to_b_buf).unwrap();
        let socket_addr_a = std::net::SocketAddr::V4(ip_a);
        let mut ip_addr_port_a = match socket_addr_a.ip() {
            std::net::IpAddr::V4(ipv4) => ipv4.octets().to_vec(),
            std::net::IpAddr::V6(ipv6) => ipv6.octets().to_vec(),
        };

        ip_addr_port_a.extend_from_slice(&socket_addr_a.port().to_be_bytes());

        let ip_addr_port_a: VecHostIdentifier = ip_addr_port_a.into();

        //B handles handshake under load, should send cookie reply message with invalid cookie
        let HandleMsgResult { resp, .. } = b
            .handle_msg_under_load(
                &a_to_b_buf.as_slice()[..init_hello_len],
                &mut *b_to_a_buf,
                &ip_addr_port_a,
            )
            .unwrap();

        let cookie_reply_len = resp.unwrap();

        //A handles cookie reply message
        a.handle_msg(&b_to_a_buf[..cookie_reply_len], &mut *a_to_b_buf)
            .unwrap();

        assert_eq!(PeerPtr(0).cv().lifecycle(&a), Lifecycle::Young);

        let expected_cookie_value =
            crate::hash_domains::cookie_value(protocol_version.keyed_hash())
                .unwrap()
                .mix(
                    b.active_or_retired_cookie_secrets()[0]
                        .unwrap()
                        .get(&b)
                        .value
                        .secret(),
                )
                .unwrap()
                .mix(ip_addr_port_a.encode())
                .unwrap()
                .into_value()[..16]
                .to_vec();

        assert_eq!(
            PeerPtr(0).cv().get(&a).map(|x| &x.value.secret()[..]),
            Some(&expected_cookie_value[..])
        );

        let retx_init_hello_len = loop {
            match a.poll().unwrap() {
                PollResult::SendRetransmission(peer) => {
                    break a.retransmit_handshake(peer, &mut *a_to_b_buf).unwrap();
                }
                PollResult::Sleep(time) => {
                    std::thread::sleep(Duration::from_secs_f64(time));
                }
                _ => {}
            }
        };

        let retx_msg_type: MsgType = a_to_b_buf.value[0].try_into().unwrap();
        assert_eq!(retx_msg_type, MsgType::InitHello);

        //B handles retransmitted message
        let HandleMsgResult { resp, .. } = b
            .handle_msg_under_load(
                &a_to_b_buf.as_slice()[..retx_init_hello_len],
                &mut *b_to_a_buf,
                &ip_addr_port_a,
            )
            .unwrap();

        let _resp_hello_len = resp.unwrap();

        let resp_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();
        assert_eq!(resp_msg_type, MsgType::RespHello);
    });
}

#[test]
#[serial]
#[cfg(feature = "experiment_cookie_dos_mitigation")]
fn cookie_reply_mechanism_initiator_bails_on_message_under_load_v02() {
    cookie_reply_mechanism_initiator_bails_on_message_under_load(ProtocolVersion::V02)
}

#[test]
#[serial]
#[cfg(feature = "experiment_cookie_dos_mitigation")]
fn cookie_reply_mechanism_initiator_bails_on_message_under_load_v03() {
    cookie_reply_mechanism_initiator_bails_on_message_under_load(ProtocolVersion::V03)
}

#[cfg(feature = "experiment_cookie_dos_mitigation")]
fn cookie_reply_mechanism_initiator_bails_on_message_under_load(protocol_version: ProtocolVersion) {
    setup_logging();
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    stacker::grow(8 * 1024 * 1024, || {
        type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
        let (mut a, mut b) = make_server_pair(protocol_version).unwrap();

        let mut a_to_b_buf = MsgBufPlus::zero();
        let mut b_to_a_buf = MsgBufPlus::zero();

        let ip_a: SocketAddrV4 = "127.0.0.1:8080".parse().unwrap();
        let mut ip_addr_port_a = ip_a.ip().octets().to_vec();
        ip_addr_port_a.extend_from_slice(&ip_a.port().to_be_bytes());
        let ip_b: SocketAddrV4 = "127.0.0.1:8081".parse().unwrap();

        //A initiates handshake
        let init_hello_len = a.initiate_handshake(PeerPtr(0), &mut *a_to_b_buf).unwrap();

        //B handles InitHello message, should respond with RespHello
        let HandleMsgResult { resp, .. } = b
            .handle_msg(&a_to_b_buf.as_slice()[..init_hello_len], &mut *b_to_a_buf)
            .unwrap();

        let resp_hello_len = resp.unwrap();
        let resp_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();
        assert_eq!(resp_msg_type, MsgType::RespHello);

        let socket_addr_b = std::net::SocketAddr::V4(ip_b);
        let mut ip_addr_port_b = [0u8; 18];
        let mut ip_addr_port_b_len = 0;
        match socket_addr_b.ip() {
            std::net::IpAddr::V4(ipv4) => {
                ip_addr_port_b[0..4].copy_from_slice(&ipv4.octets());
                ip_addr_port_b_len += 4;
            }
            std::net::IpAddr::V6(ipv6) => {
                ip_addr_port_b[0..16].copy_from_slice(&ipv6.octets());
                ip_addr_port_b_len += 16;
            }
        };

        ip_addr_port_b[ip_addr_port_b_len..ip_addr_port_b_len + 2]
            .copy_from_slice(&socket_addr_b.port().to_be_bytes());
        ip_addr_port_b_len += 2;

        let ip_addr_port_b: VecHostIdentifier =
            ip_addr_port_b[..ip_addr_port_b_len].to_vec().into();

        //A handles RespHello message under load, should not send cookie reply
        assert!(a
            .handle_msg_under_load(
                &b_to_a_buf[..resp_hello_len],
                &mut *a_to_b_buf,
                &ip_addr_port_b
            )
            .is_err());
    });
}

#[test]
fn init_conf_retransmission_v02() -> Result<()> {
    init_conf_retransmission(ProtocolVersion::V02)
}

#[test]
fn init_conf_retransmission_v03() -> Result<()> {
    init_conf_retransmission(ProtocolVersion::V03)
}

fn init_conf_retransmission(protocol_version: ProtocolVersion) -> anyhow::Result<()> {
    rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();

    fn keypair() -> Result<(SSk, SPk)> {
        let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
        StaticKem.keygen(sk.secret_mut(), pk.deref_mut())?;
        Ok((sk, pk))
    }

    fn proc_initiation(srv: &mut CryptoServer, peer: PeerPtr) -> Result<Envelope<InitHello>> {
        let mut buf = MsgBuf::zero();
        srv.initiate_handshake(peer, buf.as_mut_slice())?
            .discard_result();
        let msg = truncating_cast_into::<Envelope<InitHello>>(buf.borrow_mut())?;
        Ok(msg.read())
    }

    fn proc_msg<Rx: AsBytes + FromBytes, Tx: AsBytes + FromBytes>(
        srv: &mut CryptoServer,
        rx: &Envelope<Rx>,
    ) -> anyhow::Result<Envelope<Tx>> {
        let mut buf = MsgBuf::zero();
        srv.handle_msg(rx.as_bytes(), buf.as_mut_slice())?
            .resp
            .context("Failed to produce RespHello message")?
            .discard_result();
        let msg = truncating_cast_into::<Envelope<Tx>>(buf.borrow_mut())?;
        Ok(msg.read())
    }

    fn proc_init_hello(
        srv: &mut CryptoServer,
        ih: &Envelope<InitHello>,
    ) -> anyhow::Result<Envelope<RespHello>> {
        proc_msg::<InitHello, RespHello>(srv, ih)
    }

    fn proc_resp_hello(
        srv: &mut CryptoServer,
        rh: &Envelope<RespHello>,
    ) -> anyhow::Result<Envelope<InitConf>> {
        proc_msg::<RespHello, InitConf>(srv, rh)
    }

    fn proc_init_conf(
        srv: &mut CryptoServer,
        rh: &Envelope<InitConf>,
    ) -> anyhow::Result<Envelope<EmptyData>> {
        proc_msg::<InitConf, EmptyData>(srv, rh)
    }

    fn poll(srv: &mut CryptoServer) -> anyhow::Result<()> {
        // Discard all events; just apply the side effects
        while !matches!(srv.poll()?, PollResult::Sleep(_)) {}
        Ok(())
    }

    // TODO: Implement Clone on our message types
    fn clone_msg<Msg: AsBytes + FromBytes>(msg: &Msg) -> anyhow::Result<Msg> {
        Ok(truncating_cast_into_nomut::<Msg>(msg.as_bytes())?.read())
    }

    fn break_payload<Msg: AsBytes + FromBytes>(
        srv: &mut CryptoServer,
        peer: PeerPtr,
        msg: &Envelope<Msg>,
    ) -> anyhow::Result<Envelope<Msg>> {
        let mut msg = clone_msg(msg)?;
        msg.as_bytes_mut()[memoffset::offset_of!(Envelope<Msg>, payload)] ^= 0x01;
        msg.seal(peer, srv)?; // Recalculate seal; we do not want to focus on "seal broken" errs
        Ok(msg)
    }

    fn check_faulty_proc_init_conf(srv: &mut CryptoServer, ic_broken: &Envelope<InitConf>) {
        let mut buf = MsgBuf::zero();
        let res = srv.handle_msg(ic_broken.as_bytes(), buf.as_mut_slice());
        assert!(res.is_err());
    }

    // we this as a closure in orer to use the protocol_version variable in it.
    let check_retransmission = |srv: &mut CryptoServer,
                                ic: &Envelope<InitConf>,
                                ic_broken: &Envelope<InitConf>,
                                rc: &Envelope<EmptyData>|
     -> Result<()> {
        // Processing the same RespHello package again leads to retransmission (i.e. exactly the
        // same output)
        let rc_dup = proc_init_conf(srv, ic)?;
        assert_eq!(rc.as_bytes(), rc_dup.as_bytes());

        // Though if we directly call handle_resp_hello() we get an error since
        // retransmission is not being handled by the cryptographic code
        let mut discard_resp_conf = EmptyData::new_zeroed();
        let res = srv.handle_init_conf(
            &ic.payload,
            &mut discard_resp_conf,
            protocol_version.clone().keyed_hash(),
        );
        assert!(res.is_err());

        // Obviously, a broken InitConf message should still be rejected
        check_faulty_proc_init_conf(srv, ic_broken);

        Ok(())
    };

    let (ska, pka) = keypair()?;
    let (skb, pkb) = keypair()?;

    // initialize server and a pre-shared key
    let mut a = CryptoServer::new(ska, pka.clone());
    let mut b = CryptoServer::new(skb, pkb.clone());

    // introduce peers to each other
    let b_peer = a.add_peer(None, pkb, protocol_version.clone())?;
    let a_peer = b.add_peer(None, pka, protocol_version.clone())?;

    // Execute protocol up till the responder confirmation (EmptyData)
    let ih1 = proc_initiation(&mut a, b_peer)?;
    let rh1 = proc_init_hello(&mut b, &ih1)?;
    let ic1 = proc_resp_hello(&mut a, &rh1)?;
    let rc1 = proc_init_conf(&mut b, &ic1)?;

    // Modified version of ic1 and rc1, for tests that require it
    let ic1_broken = break_payload(&mut a, b_peer, &ic1)?;
    assert_ne!(ic1.as_bytes(), ic1_broken.as_bytes());

    // Modified version of rc1, for tests that require it
    let rc1_broken = break_payload(&mut b, a_peer, &rc1)?;
    assert_ne!(rc1.as_bytes(), rc1_broken.as_bytes());

    // Retransmission works as designed
    check_retransmission(&mut b, &ic1, &ic1_broken, &rc1)?;

    // Even with a couple of poll operations in between (which clears the cache
    // after a time out of two minutes…we should never hit this time out in this
    // cache)
    for _ in 0..4 {
        poll(&mut b)?;
        check_retransmission(&mut b, &ic1, &ic1_broken, &rc1)?;
    }
    // We can even validate that the data is coming out of the cache by changing the cache
    // to use our broken messages. It does not matter that these messages are cryptographically
    // broken since we insert them manually into the cache
    // a_peer.known_init_conf_response()
    KnownInitConfResponsePtr::insert_for_request_msg(
        &mut b,
        a_peer,
        &ic1_broken,
        rc1_broken.clone(),
    );
    check_retransmission(&mut b, &ic1_broken, &ic1, &rc1_broken)?;

    // Lets reset to the correct message though
    KnownInitConfResponsePtr::insert_for_request_msg(&mut b, a_peer, &ic1, rc1.clone());

    // Again, nothing changes after calling poll
    poll(&mut b)?;
    check_retransmission(&mut b, &ic1, &ic1_broken, &rc1)?;

    // Except if we jump forward into the future past the point where the responder
    // starts to initiate rekeying; in this case, the automatic time out is triggered and the cache is cleared
    super::testutils::time_travel_forward(&mut b, REKEY_AFTER_TIME_RESPONDER);

    // As long as we do not call poll, everything is fine
    check_retransmission(&mut b, &ic1, &ic1_broken, &rc1)?;

    // But after we do, the response is gone and can not be recreated
    // since the biscuit is stale
    poll(&mut b)?;
    check_faulty_proc_init_conf(&mut b, &ic1); // ic1 is now effectively broken
    assert!(b.peers[0].known_init_conf_response.is_none()); // The cache is gone

    Ok(())
}
