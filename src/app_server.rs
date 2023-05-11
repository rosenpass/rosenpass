use anyhow::bail;

use anyhow::Result;
use log::{error, info, warn};
use mio::Interest;
use mio::Token;

use std::io::Write;

use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::time::Duration;

use crate::util::fopen_w;
use crate::{
    config::Verbosity,
    protocol::{CryptoServer, MsgBuf, PeerPtr, SPk, SSk, SymKey, Timing},
    util::{b64_writer, fmt_b64},
};

const IPV4_ANY_ADDR: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const IPV6_ANY_ADDR: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);

fn ipv4_any_binding() -> SocketAddr {
    // addr, port
    SocketAddr::V4(SocketAddrV4::new(IPV4_ANY_ADDR, 0))
}

fn ipv6_any_binding() -> SocketAddr {
    // addr, port, flowinfo, scope_id
    SocketAddr::V6(SocketAddrV6::new(IPV6_ANY_ADDR, 0, 0, 0))
}

#[derive(Default, Debug)]
pub struct AppPeer {
    pub outfile: Option<PathBuf>,
    pub outwg: Option<WireguardOut>, // TODO make this a generic command
    pub tx_addr: Option<SocketAddr>,
}

#[derive(Default, Debug)]
pub struct WireguardOut {
    // impl KeyOutput
    pub dev: String,
    pub pk: String,
    pub extra_params: Vec<String>,
}

/// Holds the state of the application, namely the external IO
///
/// Responsible for file IO, network IO
// TODO add user control via unix domain socket and stdin/stdout
#[derive(Debug)]
pub struct AppServer {
    pub crypt: CryptoServer,
    pub sockets: Vec<mio::net::UdpSocket>,
    pub events: mio::Events,
    pub mio_poll: mio::Poll,
    pub peers: Vec<AppPeer>,
    pub verbosity: Verbosity,
    pub all_sockets_drained: bool,
}

/// Index based pointer to a Peer
#[derive(Debug)]
pub struct AppPeerPtr(pub usize);

impl AppPeerPtr {
    /// Takes an index based handle and returns the actual peer
    pub fn lift(p: PeerPtr) -> Self {
        Self(p.0)
    }

    /// Returns an index based handle to one Peer
    pub fn lower(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    pub fn get_app<'a>(&self, srv: &'a AppServer) -> &'a AppPeer {
        &srv.peers[self.0]
    }

    pub fn get_app_mut<'a>(&self, srv: &'a mut AppServer) -> &'a mut AppPeer {
        &mut srv.peers[self.0]
    }
}

#[derive(Debug)]
pub enum AppPollResult {
    DeleteKey(AppPeerPtr),
    SendInitiation(AppPeerPtr),
    SendRetransmission(AppPeerPtr),
    ReceivedMessage(usize, SocketAddr),
}

#[derive(Debug)]
pub enum KeyOutputReason {
    Exchanged,
    Stale,
}

impl AppServer {
    pub fn new(
        sk: SSk,
        pk: SPk,
        addrs: Vec<SocketAddr>,
        verbosity: Verbosity,
    ) -> anyhow::Result<Self> {
        // setup mio
        let mio_poll = mio::Poll::new()?;
        let events = mio::Events::with_capacity(8);

        // bind each SocketAddr to a socket
        let maybe_sockets: Result<Vec<_>, _> =
            addrs.into_iter().map(mio::net::UdpSocket::bind).collect();
        let mut sockets = maybe_sockets?;

        // When no socket is specified, rosenpass should open one port on all
        // available interfaces best-effort. Here are the cases how this can possibly go:
        //
        // Some operating systems (such as linux [^linux] and freebsd [^freebsd])
        // using IPv6 sockets to handle IPv4 connections; on these systems
        // binding to the `[::]:0` address will typically open a dual-stack
        // socket. Some other systems such as openbsd [^openbsd] do not support this feature.
        //
        // Dual-stack systems provide a flag to enable or disable this
        // behavior – the IPV6_V6ONLY flag. Openbsd supports this flag
        // read-only. MIO[^mio] provides a way to read this flag but not
        // to write it.
        //
        // - One dual-stack IPv6 socket, if the operating supports dual-stack sockets and
        //   correctly reports this
        // - One IPv6 socket and one IPv4 socket if the operating does not support dual stack
        //   sockets or disables them by default assuming this is also correctly reported
        // - One IPv6 socket and no IPv4 socket if IPv6 socket is not dual-stack and opening
        //   the IPv6 socket fails
        // - One IPv4 socket and no IPv6 socket if opening the IPv6 socket fails
        // - One dual-stack IPv6 socket and a redundant IPv4 socket if dual-stack sockets are
        //   supported but the operating system does not correctly report this (specifically,
        //   if the only_v6() call raises an errror)
        // - Rosenpass exits if no socket could be opened
        //
        // [^freebsd]: https://man.freebsd.org/cgi/man.cgi?query=ip6&sektion=4&manpath=FreeBSD+6.0-RELEASE
        // [^openbsd]: https://man.openbsd.org/ip6.4
        // [^linux]: https://man7.org/linux/man-pages/man7/ipv6.7.html
        // [^mio]: https://docs.rs/mio/0.8.6/mio/net/struct.UdpSocket.html#method.only_v6
        if sockets.is_empty() {
            macro_rules! try_register_socket {
                ($title:expr, $binding:expr) => {{
                    let r = mio::net::UdpSocket::bind($binding);
                    match r {
                        Ok(sock) => {
                            sockets.push(sock);
                            Some(sockets.len() - 1)
                        }
                        Err(e) => {
                            warn!("Could not bind to {} socket: {}", $title, e);
                            None
                        }
                    }
                }};
            }

            let v6 = try_register_socket!("IPv6", ipv6_any_binding());

            let need_v4 = match v6.map(|no| sockets[no].only_v6()) {
                Some(Ok(v)) => v,
                None => true,
                Some(Err(e)) => {
                    warn!("Unable to detect whether the IPv6 socket supports dual-stack operation: {}", e);
                    true
                }
            };

            if need_v4 {
                try_register_socket!("IPv4", ipv4_any_binding());
            }
        }

        if sockets.is_empty() {
            bail!("No sockets to listen on!")
        }

        // register all sockets to mio
        for (i, socket) in sockets.iter_mut().enumerate() {
            mio_poll
                .registry()
                .register(socket, Token(i), Interest::READABLE)?;
        }

        // TODO use mio::net::UnixStream together with std::os::unix::net::UnixStream for linux

        Ok(Self {
            crypt: CryptoServer::new(sk, pk),
            peers: Vec::new(),
            verbosity,
            sockets,
            events,
            mio_poll,
            all_sockets_drained: false,
        })
    }

    pub fn verbose(&self) -> bool {
        matches!(self.verbosity, Verbosity::Verbose)
    }

    pub fn add_peer(
        &mut self,
        psk: Option<SymKey>,
        pk: SPk,
        outfile: Option<PathBuf>,
        outwg: Option<WireguardOut>,
        tx_addr: Option<SocketAddr>,
    ) -> anyhow::Result<AppPeerPtr> {
        let PeerPtr(pn) = self.crypt.add_peer(psk, pk)?;
        assert!(pn == self.peers.len());
        self.peers.push(AppPeer {
            outfile,
            outwg,
            tx_addr,
        });
        Ok(AppPeerPtr(pn))
    }

    pub fn listen_loop(&mut self) -> anyhow::Result<()> {
        const INIT_SLEEP: f64 = 0.01;
        const MAX_FAILURES: i32 = 10;
        let mut failure_cnt = 0;

        loop {
            let msgs_processed = 0usize;
            let err = match self.event_loop() {
                Ok(()) => return Ok(()),
                Err(e) => e,
            };

            // This should not happen…
            failure_cnt = if msgs_processed > 0 {
                0
            } else {
                failure_cnt + 1
            };
            let sleep = INIT_SLEEP * 2.0f64.powf(f64::from(failure_cnt - 1));
            let tries_left = MAX_FAILURES - (failure_cnt - 1);
            error!(
                "unexpected error after processing {} messages: {:?} {}",
                msgs_processed,
                err,
                err.backtrace()
            );
            if tries_left > 0 {
                error!("reinitializing networking in {sleep}! {tries_left} tries left.");
                std::thread::sleep(self.crypt.timebase.dur(sleep));
                continue;
            }

            bail!("too many network failures");
        }
    }

    pub fn event_loop(&mut self) -> anyhow::Result<()> {
        let (mut rx, mut tx) = (MsgBuf::zero(), MsgBuf::zero());

        /// if socket address for peer is known, call closure
        /// assumes that closure leaves a message in `tx`
        /// assumes that closure returns the length of message in bytes
        macro_rules! tx_maybe_with {
            ($peer:expr, $fn:expr) => {
                attempt!({
                    let p = $peer.get_app(self);
                    if let Some(addr) = p.tx_addr {
                        let len = $fn()?;
                        self.try_send(&tx[..len], addr)?;
                    }
                    Ok(())
                })
            };
        }

        loop {
            use crate::protocol::HandleMsgResult;
            use AppPollResult::*;
            use KeyOutputReason::*;
            match self.poll(&mut *rx)? {
                SendInitiation(peer) => tx_maybe_with!(peer, || self
                    .crypt
                    .initiate_handshake(peer.lower(), &mut *tx))?,
                SendRetransmission(peer) => tx_maybe_with!(peer, || self
                    .crypt
                    .retransmit_handshake(peer.lower(), &mut *tx))?,
                DeleteKey(peer) => self.output_key(peer, Stale, &SymKey::random())?,

                ReceivedMessage(len, addr) => {
                    match self.crypt.handle_msg(&rx[..len], &mut *tx) {
                        Err(ref e) => {
                            self.verbose().then(|| {
                                info!(
                                    "error processing incoming message from {:?}: {:?} {}",
                                    addr,
                                    e,
                                    e.backtrace()
                                );
                            });
                        }

                        Ok(HandleMsgResult {
                            resp,
                            exchanged_with,
                            ..
                        }) => {
                            if let Some(len) = resp {
                                self.try_send(&tx[0..len], addr)?;
                            }

                            if let Some(p) = exchanged_with {
                                let ap = AppPeerPtr::lift(p);
                                ap.get_app_mut(self).tx_addr = Some(addr);

                                // TODO: Maybe we should rather call the key "rosenpass output"?
                                self.output_key(ap, Exchanged, &self.crypt.osk(p)?)?;
                            }
                        }
                    }
                }
            };
        }
    }

    pub fn output_key(
        &self,
        peer: AppPeerPtr,
        why: KeyOutputReason,
        key: &SymKey,
    ) -> anyhow::Result<()> {
        let peerid = peer.lower().get(&self.crypt).pidt()?;
        let ap = peer.get_app(self);

        if self.verbose() {
            let msg = match why {
                KeyOutputReason::Exchanged => "Exchanged key with peer",
                KeyOutputReason::Stale => "Erasing outdated key from peer",
            };
            info!("{} {}", msg, fmt_b64(&*peerid));
        }

        if let Some(of) = ap.outfile.as_ref() {
            // This might leave some fragments of the secret on the stack;
            // in practice this is likely not a problem because the stack likely
            // will be overwritten by something else soon but this is not exactly
            // guaranteed. It would be possible to remedy this, but since the secret
            // data will linger in the linux page cache anyways with the current
            // implementation, going to great length to erase the secret here is
            // not worth it right now.
            b64_writer(fopen_w(of)?).write_all(key.secret())?;
            let why = match why {
                KeyOutputReason::Exchanged => "exchanged",
                KeyOutputReason::Stale => "stale",
            };

            // this is intentionally writing to stdout instead of stderr, because
            // it is meant to allow external detection of a succesful key-exchange
            println!(
                "output-key peer {} key-file {of:?} {why}",
                fmt_b64(&*peerid)
            );
        }

        if let Some(owg) = ap.outwg.as_ref() {
            let child = Command::new("wg")
                .arg("set")
                .arg(&owg.dev)
                .arg("peer")
                .arg(&owg.pk)
                .arg("preshared-key")
                .arg("/dev/stdin")
                .stdin(Stdio::piped())
                .args(&owg.extra_params)
                .spawn()?;
            b64_writer(child.stdin.unwrap()).write_all(key.secret())?;
        }

        Ok(())
    }

    pub fn poll(&mut self, rx_buf: &mut [u8]) -> anyhow::Result<AppPollResult> {
        use crate::protocol::PollResult as C;
        use AppPollResult as A;
        loop {
            return Ok(match self.crypt.poll()? {
                C::DeleteKey(PeerPtr(no)) => A::DeleteKey(AppPeerPtr(no)),
                C::SendInitiation(PeerPtr(no)) => A::SendInitiation(AppPeerPtr(no)),
                C::SendRetransmission(PeerPtr(no)) => A::SendRetransmission(AppPeerPtr(no)),
                C::Sleep(timeout) => match self.try_recv(rx_buf, timeout)? {
                    Some((len, addr)) => A::ReceivedMessage(len, addr),
                    None => continue,
                },
            });
        }
    }

    /// Tries to receive a new message
    ///
    /// - might wait for an duration up to `timeout`
    /// - returns immediately if an error occurs
    /// - returns immediately if a new message is received
    pub fn try_recv(
        &mut self,
        buf: &mut [u8],
        timeout: Timing,
    ) -> anyhow::Result<Option<(usize, SocketAddr)>> {
        let timeout = Duration::from_secs_f64(timeout);

        // if there is no time to wait on IO, well, then, lets not waste any time!
        if timeout.is_zero() {
            return Ok(None);
        }

        // NOTE when using mio::Poll, there are some finickies (taken from
        // https://docs.rs/mio/latest/mio/struct.Poll.html):
        //
        // - poll() might return readiness, even if nothing is ready
        // - in this case, a WouldBlock error is returned from actual IO operations
        // - after receiving readiness for a source, it must be drained until a WouldBlock
        //   is received
        //
        // This would ususally require us to maintain the drainage status of each socket;
        // a socket would only become drained when it returned WouldBlock and only
        // non-drained when receiving a readiness event from mio for it. Then, only the
        // ready sockets should be worked on, ideally without requiring an O(n) search
        // through all sockets for checking their drained status. However, our use-case
        // is primarily heaving one or two sockets (if IPv4 and IPv6 IF_ANY listen is
        // desired on a non-dual-stack OS), thus just checking every socket after any
        // readiness event seems to be good enough™ for now.

        // only poll if we drained all sockets before
        if self.all_sockets_drained {
            self.mio_poll.poll(&mut self.events, Some(timeout))?;
        }

        let mut would_block_count = 0;
        for socket in &mut self.sockets {
            match socket.recv_from(buf) {
                Ok(x) => {
                    // at least one socket was not drained...
                    self.all_sockets_drained = false;
                    return Ok(Some(x));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    would_block_count += 1;
                }
                // TODO if one socket continuesly returns an error, then we never poll, thus we never wait for a timeout, thus we have a spin-lock
                Err(e) => return Err(e.into()),
            }
        }

        // if each socket returned WouldBlock, then we drained them all at least once indeed
        self.all_sockets_drained = would_block_count == self.sockets.len();

        Ok(None)
    }

    /// Try to send a message
    ///
    /// Every available socket is tried once
    // TODO cache what socket worked last time
    // TODO cache what socket we received from last time for that addr
    pub fn try_send(&mut self, buf: &[u8], addr: SocketAddr) -> anyhow::Result<()> {
        for socket in &self.sockets {
            return match socket.send_to(&buf, addr) {
                Ok(_) => Ok(()),

                // TODO replace this by
                // Err(e) if e.kind() == io::ErrorKind::NetworkUnreachable => continue,
                // once https://github.com/rust-lang/rust/issues/86442 lands
                Err(e)
                    if e.to_string()
                        .starts_with("Address family not supported by protocol") =>
                {
                    continue
                }
                Err(e) => Err(e.into()),
            };
        }

        bail!("none of our sockets matched the address family {}", addr);
    }
}
