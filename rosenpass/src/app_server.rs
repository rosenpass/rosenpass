use anyhow::bail;

use anyhow::Result;
use log::{debug, error, info, warn};
use mio::Interest;
use mio::Token;

use std::cell::Cell;
use std::io::Write;

use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::net::SocketAddrV4;
use std::net::SocketAddrV6;
use std::net::ToSocketAddrs;
use std::path::PathBuf;
use std::process::Command;
use std::process::Stdio;
use std::slice;
use std::thread;
use std::time::Duration;

use crate::util::fopen_w;
use crate::{
    config::Verbosity,
    protocol::{CryptoServer, MsgBuf, PeerPtr, SPk, SSk, SymKey, Timing},
};
use rosenpass_util::attempt;
use rosenpass_util::b64::{b64_writer, fmt_b64};

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
    pub initial_endpoint: Option<Endpoint>,
    pub current_endpoint: Option<Endpoint>,
}

impl AppPeer {
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.current_endpoint
            .as_ref()
            .or(self.initial_endpoint.as_ref())
    }
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

/// A socket pointer is an index assigned to a socket;
/// right now the index is just the sockets index in AppServer::sockets.
///
/// Holding this as a reference instead of an &mut UdpSocket is useful
/// to deal with the borrow checker, because otherwise we could not refer
/// to a socket and another member of AppServer at the same time.
#[derive(Debug)]
pub struct SocketPtr(pub usize);

impl SocketPtr {
    pub fn get<'a>(&self, srv: &'a AppServer) -> &'a mio::net::UdpSocket {
        &srv.sockets[self.0]
    }

    pub fn get_mut<'a>(&self, srv: &'a mut AppServer) -> &'a mut mio::net::UdpSocket {
        &mut srv.sockets[self.0]
    }

    pub fn send_to(&self, srv: &AppServer, buf: &[u8], addr: SocketAddr) -> anyhow::Result<()> {
        self.get(srv).send_to(buf, addr)?;
        Ok(())
    }
}

/// Index based pointer to a Peer
#[derive(Debug, Copy, Clone)]
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
    ReceivedMessage(usize, Endpoint),
}

#[derive(Debug)]
pub enum KeyOutputReason {
    Exchanged,
    Stale,
}

/// Represents a communication partner rosenpass may be sending packets to
///
/// Generally at the start of Rosenpass either no address or a Hostname is known;
/// later when we actually start to receive RespHello packages, we know the specific Address
/// and socket to use with a peer
#[derive(Debug)]
pub enum Endpoint {
    /// Rosenpass supports multiple sockets, so we include the information
    /// which socket an address can be reached on. This probably does not
    /// make much of a difference in most setups where two sockets are just
    /// used to enable dual stack operation; it does make a difference in
    /// more complex use cases.
    ///
    /// For instance it enables using multiple interfaces with overlapping
    /// ip spaces, such as listening on a private IP network and a public IP
    /// at the same time. It also would reply on the same port RespHello was
    /// sent to when listening on multiple ports on the same interface. This
    /// may be required for some arcane firewall setups.
    SocketBoundAddress {
        /// The socket the address can be reached under; this is generally
        /// determined when we actually receive an RespHello message
        socket: SocketPtr,
        /// Just the address
        addr: SocketAddr,
    },
    // A host name or IP address; storing the hostname here instead of an
    // ip address makes sure that we look up the host name whenever we try
    // to make a connection; this may be beneficial in some setups where a host-name
    // at first can not be resolved but becomes resolvable later.
    Discovery(HostPathDiscoveryEndpoint),
}

impl Endpoint {
    /// Start discovery from some addresses
    pub fn discovery_from_addresses(addresses: Vec<SocketAddr>) -> Self {
        Endpoint::Discovery(HostPathDiscoveryEndpoint::from_addresses(addresses))
    }

    /// Start endpoint discovery from a hostname
    pub fn discovery_from_hostname(hostname: String) -> anyhow::Result<Self> {
        let host = HostPathDiscoveryEndpoint::lookup(hostname)?;
        Ok(Endpoint::Discovery(host))
    }

    // Restart discovery; joining two sources of (potential) addresses
    //
    // This is used when the connection to an endpoint is lost in order
    // to include the addresses specified on the command line and the
    // address last used in the discovery process
    pub fn discovery_from_multiple_sources(
        a: Option<&Endpoint>,
        b: Option<&Endpoint>,
    ) -> Option<Self> {
        let sources = match (a, b) {
            (Some(e), None) | (None, Some(e)) => e.addresses().iter().chain(&[]),
            (Some(e1), Some(e2)) => e1.addresses().iter().chain(e2.addresses()),
            (None, None) => return None,
        };
        let lower_size_bound = sources.size_hint().0;
        let mut dedup = std::collections::HashSet::with_capacity(lower_size_bound);
        let mut addrs = Vec::with_capacity(lower_size_bound);
        for a in sources {
            if dedup.insert(a) {
                addrs.push(*a);
            }
        }
        Some(Self::discovery_from_addresses(addrs))
    }

    pub fn send(&self, srv: &AppServer, buf: &[u8]) -> anyhow::Result<()> {
        use Endpoint::*;
        match self {
            SocketBoundAddress { socket, addr } => socket.send_to(srv, buf, *addr),
            Discovery(host) => host.send_scouting(srv, buf),
        }
    }

    fn addresses(&self) -> &[SocketAddr] {
        use Endpoint::*;
        match self {
            SocketBoundAddress { addr, .. } => slice::from_ref(addr),
            Discovery(host) => host.addresses(),
        }
    }
}

/// Handles host-path discovery
///
/// When rosenpass is started, we either know no peer address
/// or we know a hostname. How to contact this hostname may not
/// be entirely clear for two reasons:
///
/// 1. We have multiple sockets; only a subset of those may be able to contact the host
/// 2. DNS resolution can return multiple addresses
///
/// We could just use the first working socket and the first address returned, but this
/// may be error prone: Some of the sockets may appear to be able to contact the host,
/// but the packets will be dropped. Some of the addresses may appear to be reachable
/// but the packets could be lost.
///
/// In contrast to TCP, UDP has no mechanism to ensure packets actually arrive.
///
/// To robustly handle host path discovery, we try each socket-ip-combination in a round
/// robin fashion; the struct stores the offset of the last used combination internally and
/// and will continue with the next combination on every call.
///
/// Retransmission handling will continue normally; i.e. increasing the distance between
/// retransmissions on every retransmission, until it is long enough to bore a human. Therefor
/// it is important to avoid having a large number of sockets drop packets not just for efficiency
/// but to avoid latency issues too.
///
// TODO: We might consider adjusting the retransmission handling to account for host-path discovery
#[derive(Debug)]
pub struct HostPathDiscoveryEndpoint {
    scouting_state: Cell<(usize, usize)>, // addr_off, sock_off
    addresses: Vec<SocketAddr>,
}

impl HostPathDiscoveryEndpoint {
    pub fn from_addresses(addresses: Vec<SocketAddr>) -> Self {
        let scouting_state = Cell::new((0, 0));
        Self {
            addresses,
            scouting_state,
        }
    }

    /// Lookup a hostname
    pub fn lookup(hostname: String) -> anyhow::Result<Self> {
        Ok(Self {
            addresses: ToSocketAddrs::to_socket_addrs(&hostname)?.collect(),
            scouting_state: Cell::new((0, 0)),
        })
    }

    pub fn addresses(&self) -> &Vec<SocketAddr> {
        &self.addresses
    }

    fn insert_next_scout_offset(&self, srv: &AppServer, addr_no: usize, sock_no: usize) {
        self.scouting_state.set((
            (addr_no + 1) % self.addresses.len(),
            (sock_no + 1) % srv.sockets.len(),
        ));
    }

    /// Attempt to reach the host
    ///
    /// Will round-robin-try different socket-ip-combinations on each call.
    pub fn send_scouting(&self, srv: &AppServer, buf: &[u8]) -> anyhow::Result<()> {
        let (addr_off, sock_off) = self.scouting_state.get();

        let mut addrs = (self.addresses)
            .iter()
            .enumerate()
            .cycle()
            .skip(addr_off)
            .take(self.addresses.len());
        let mut sockets = (srv.sockets)
            .iter()
            .enumerate()
            .cycle()
            .skip(sock_off)
            .take(srv.sockets.len());

        for (addr_no, addr) in addrs.by_ref() {
            for (sock_no, sock) in sockets.by_ref() {
                let res = sock.send_to(buf, *addr);
                let err = match res {
                    Ok(_) => {
                        self.insert_next_scout_offset(srv, addr_no, sock_no);
                        return Ok(());
                    }
                    Err(e) => e,
                };

                // TODO: replace this by
                // e.kind() == io::ErrorKind::NetworkUnreachable
                // once https://github.com/rust-lang/rust/issues/86442 lands
                let ignore = err
                    .to_string()
                    .starts_with("Address family not supported by protocol");
                if !ignore {
                    warn!("Socket #{} refusing to send to {}: ", sock_no, addr);
                }
            }
        }

        bail!("Unable to send message: All sockets returned errors.")
    }
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
        // Some operating systems (such as Linux [^linux] and FreeBSD [^freebsd])
        // using IPv6 sockets to handle IPv4 connections; on these systems
        // binding to the `[::]:0` address will typically open a dual-stack
        // socket. Some other systems such as OpenBSD [^openbsd] do not support this feature.
        //
        // Dual-stack systems provide a flag to enable or disable this
        // behavior – the IPV6_V6ONLY flag. OpenBSD supports this flag
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
        //   if the only_v6() call raises an error)
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

        // TODO use mio::net::UnixStream together with std::os::unix::net::UnixStream for Linux

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
        hostname: Option<String>,
    ) -> anyhow::Result<AppPeerPtr> {
        let PeerPtr(pn) = self.crypt.add_peer(psk, pk)?;
        assert!(pn == self.peers.len());
        let initial_endpoint = hostname
            .map(Endpoint::discovery_from_hostname)
            .transpose()?;
        let current_endpoint = None;
        self.peers.push(AppPeer {
            outfile,
            outwg,
            initial_endpoint,
            current_endpoint,
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
                error!("re-initializing networking in {sleep}! {tries_left} tries left.");
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
                    let p = $peer;
                    if p.get_app(self).endpoint().is_some() {
                        let len = $fn()?;
                        let ep: &Endpoint = p.get_app(self).endpoint().unwrap();
                        ep.send(self, &tx[..len])?;
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
                #[allow(clippy::redundant_closure_call)]
                SendInitiation(peer) => tx_maybe_with!(peer, || self
                    .crypt
                    .initiate_handshake(peer.lower(), &mut *tx))?,
                #[allow(clippy::redundant_closure_call)]
                SendRetransmission(peer) => tx_maybe_with!(peer, || self
                    .crypt
                    .retransmit_handshake(peer.lower(), &mut *tx))?,
                DeleteKey(peer) => {
                    self.output_key(peer, Stale, &SymKey::random())?;

                    // There was a loss of connection apparently; restart host discovery
                    // starting from the last used address but including all the initially
                    // specified addresses
                    // TODO: We could do this preemptively, before any connection loss actually occurs.
                    let p = peer.get_app_mut(self);
                    p.current_endpoint = Endpoint::discovery_from_multiple_sources(
                        p.current_endpoint.as_ref(),
                        p.initial_endpoint.as_ref(),
                    );
                }

                ReceivedMessage(len, endpoint) => {
                    match self.crypt.handle_msg(&rx[..len], &mut *tx) {
                        Err(ref e) => {
                            self.verbose().then(|| {
                                info!(
                                    "error processing incoming message from {:?}: {:?} {}",
                                    endpoint,
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
                                endpoint.send(self, &tx[0..len])?;
                            }

                            if let Some(p) = exchanged_with {
                                let ap = AppPeerPtr::lift(p);
                                ap.get_app_mut(self).current_endpoint = Some(endpoint);

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
            // it is meant to allow external detection of a successful key-exchange
            println!(
                "output-key peer {} key-file {of:?} {why}",
                fmt_b64(&*peerid)
            );
        }

        if let Some(owg) = ap.outwg.as_ref() {
            let mut child = Command::new("wg")
                .arg("set")
                .arg(&owg.dev)
                .arg("peer")
                .arg(&owg.pk)
                .arg("preshared-key")
                .arg("/dev/stdin")
                .stdin(Stdio::piped())
                .args(&owg.extra_params)
                .spawn()?;
            b64_writer(child.stdin.take().unwrap()).write_all(key.secret())?;

            thread::spawn(move || {
                let status = child.wait();

                if let Ok(status) = status {
                    if status.success() {
                        debug!("successfully passed psk to wg")
                    } else {
                        error!("could not pass psk to wg {:?}", status)
                    }
                } else {
                    error!("wait failed: {:?}", status)
                }
            });
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
    ) -> anyhow::Result<Option<(usize, Endpoint)>> {
        let timeout = Duration::from_secs_f64(timeout);

        // if there is no time to wait on IO, well, then, lets not waste any time!
        if timeout.is_zero() {
            return Ok(None);
        }

        // NOTE when using mio::Poll, there are some particularities (taken from
        // https://docs.rs/mio/latest/mio/struct.Poll.html):
        //
        // - poll() might return readiness, even if nothing is ready
        // - in this case, a WouldBlock error is returned from actual IO operations
        // - after receiving readiness for a source, it must be drained until a WouldBlock
        //   is received
        //
        // This would usually require us to maintain the drainage status of each socket;
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
        for (sock_no, socket) in self.sockets.iter_mut().enumerate() {
            match socket.recv_from(buf) {
                Ok((n, addr)) => {
                    // at least one socket was not drained...
                    self.all_sockets_drained = false;
                    return Ok(Some((
                        n,
                        Endpoint::SocketBoundAddress {
                            socket: SocketPtr(sock_no),
                            addr,
                        },
                    )));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    would_block_count += 1;
                }
                // TODO if one socket continuously returns an error, then we never poll, thus we never wait for a timeout, thus we have a spin-lock
                Err(e) => return Err(e.into()),
            }
        }

        // if each socket returned WouldBlock, then we drained them all at least once indeed
        self.all_sockets_drained = would_block_count == self.sockets.len();

        Ok(None)
    }
}
