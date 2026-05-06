//! This contains the bulk of the rosenpass server IO handling code whereas
//! the actual cryptographic code lives in the [crate::protocol] module

use std::collections::{HashMap, VecDeque};
use std::io::{stdout, ErrorKind, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{cell::Cell, fmt::Debug, io, path::PathBuf, slice};

use mio::{Interest, Token};
#[cfg(unix)]
use signal_hook_mio::v1_0 as signal_hook_mio;
use anyhow::{bail, Context, Result};
use derive_builder::Builder;
use log::{error, info, warn};
use zerocopy::AsBytes;

use rosenpass_util::attempt;
use rosenpass_util::fmt::debug::NullDebug;
use rosenpass_util::functional::{run, ApplyExt};
use rosenpass_util::io::{IoResultKindHintExt, SubstituteForIoErrorKindExt};
use rosenpass_util::{
    b64::B64Display, build::ConstructionSite, file::StoreValueB64, result::OkExt,
};

use rosenpass_secret_memory::{Public, Secret};
use rosenpass_wireguard_broker::{WireguardBrokerCfg, WireguardBrokerMio, WG_KEY_LEN};

use crate::config::{ProtocolVersion, Verbosity};

use crate::protocol::basic_types::{MsgBuf, SPk, SSk, SymKey};
use crate::protocol::osk_domain_separator::OskDomainSeparator;
use crate::protocol::timing::Timing;
use crate::protocol::{BuildCryptoServer, CryptoServer, HostIdentification, PeerPtr};

pub const MAX_B64_KEY_SIZE: usize = 32 * 5 / 3;
pub const MAX_B64_PEER_ID_SIZE: usize = 32 * 5 / 3;

const IPV4_ANY_ADDR: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);
const IPV6_ANY_ADDR: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0);
const UNDER_LOAD_RATIO: f64 = 0.5;
const DURATION_UPDATE_UNDER_LOAD_STATUS: Duration = Duration::from_millis(500);
pub const BROKER_ID_BYTES: usize = 8;

pub fn ipv4_any_binding() -> SocketAddr {
    SocketAddr::V4(SocketAddrV4::new(IPV4_ANY_ADDR, 0))
}

pub fn ipv6_any_binding() -> SocketAddr {
    SocketAddr::V6(SocketAddrV6::new(IPV6_ANY_ADDR, 0, 0, 0))
}

#[derive(Debug, Default)]
pub struct MioTokenDispenser {
    pub counter: usize,
}

impl MioTokenDispenser {
    pub fn dispense(&mut self) -> Token {
        let r = self.counter;
        self.counter += 1;
        Token(r)
    }
}

#[derive(Debug, Default)]
pub struct BrokerStore {
    pub store: HashMap<
        Public<BROKER_ID_BYTES>,
        Box<dyn WireguardBrokerMio<Error = anyhow::Error, MioError = anyhow::Error> + Send>,
    >,
}

#[derive(Debug, Clone)]
pub struct BrokerStorePtr(pub Public<BROKER_ID_BYTES>);

#[derive(Debug)]
pub struct BrokerPeer {
    ptr: BrokerStorePtr,
    peer_cfg: Box<dyn WireguardBrokerCfg + Send>,
}

impl BrokerPeer {
    pub fn new(ptr: BrokerStorePtr, peer_cfg: Box<dyn WireguardBrokerCfg + Send>) -> Self {
        Self { ptr, peer_cfg }
    }
    pub fn ptr(&self) -> &BrokerStorePtr {
        &self.ptr
    }
}

#[derive(Default, Debug)]
pub struct AppPeer {
    pub outfile: Option<PathBuf>,
    pub broker_peer: Option<BrokerPeer>,
    pub initial_endpoint: Option<Endpoint>,
    pub current_endpoint: Option<Endpoint>,
}

impl AppPeer {
    pub fn endpoint(&self) -> Option<&Endpoint> {
        self.current_endpoint.as_ref().or(self.initial_endpoint.as_ref())
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DoSOperation {
    UnderLoad,
    Normal,
}

#[derive(Debug, Builder)]
#[builder(pattern = "owned")]
pub struct AppServerTest {
    #[builder(default = "false")]
    pub enable_dos_permanently: bool,
    #[builder(default = "None")]
    pub termination_handler: Option<std::sync::mpsc::Receiver<()>>,
}

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum AppServerIoSource {
    Socket(usize),
    PskBroker(Public<BROKER_ID_BYTES>),
    SignalHandler,
    #[cfg(feature = "experiment_api")]
    MioManager(crate::api::mio::MioManagerIoSource),
}

pub enum AppServerTryRecvResult {
    None,
    Terminate,
    NetworkMessage(usize, Endpoint),
}

const EVENT_CAPACITY: usize = 20;

#[derive(Debug)]
pub struct AppServer {
    pub crypto_site: ConstructionSite<BuildCryptoServer, CryptoServer>,
    pub sockets: Vec<mio::net::UdpSocket>,
    pub events: mio::Events,
    pub short_poll_queue: VecDeque<mio::event::Event>,
    pub performed_long_poll: bool,
    pub io_source_index: HashMap<mio::Token, AppServerIoSource>,
    pub mio_poll: mio::Poll,
    pub mio_token_dispenser: MioTokenDispenser,
    pub signal_handler: NullDebug<signal_hook_mio::Signals>,
    pub brokers: BrokerStore,
    pub peers: Vec<AppPeer>,
    pub verbosity: Verbosity,
    pub all_sockets_drained: bool,
    pub under_load: DoSOperation,
    pub blocking_polls_count: usize,
    pub non_blocking_polls_count: usize,
    pub unpolled_count: usize,
    pub last_update_time: Instant,
    pub test_helpers: Option<AppServerTest>,
    #[cfg(feature = "experiment_api")]
    pub api_manager: crate::api::mio::MioManager,
}

#[derive(Debug)]
pub struct SocketPtr(pub usize);

impl SocketPtr {
    pub fn get<'a>(&self, srv: &'a AppServer) -> &'a mio::net::UdpSocket {
        &srv.sockets[self.0]
    }
    pub fn send_to(&self, srv: &AppServer, buf: &[u8], addr: SocketAddr) -> anyhow::Result<()> {
        self.get(srv).send_to(buf, addr)?;
        Ok(())
    }
}

#[derive(Debug, Copy, Clone)]
pub struct AppPeerPtr(pub usize);

impl AppPeerPtr {
    pub fn lift(p: PeerPtr) -> Self { Self(p.0) }
    pub fn lower(&self) -> PeerPtr { PeerPtr(self.0) }
    pub fn get_app<'a>(&self, srv: &'a AppServer) -> &'a AppPeer { &srv.peers[self.0] }
    pub fn get_app_mut<'a>(&self, srv: &'a mut AppServer) -> &'a mut AppPeer { &mut srv.peers[self.0] }

    pub fn set_psk(&self, server: &mut AppServer, psk: &Secret<WG_KEY_LEN>) -> anyhow::Result<()> {
        if let Some(broker) = server.peers[self.0].broker_peer.as_ref() {
            let config = broker.peer_cfg.create_config(psk);
            let broker_obj = server.brokers.store.get_mut(&broker.ptr().0).unwrap();
            broker_obj.set_psk(config)?;
        } else if server.peers[self.0].outfile.is_none() {
            log::warn!("No broker peer found for peer {}", self.0);
        }
        Ok(())
    }
}

#[derive(Debug)]
pub enum AppPollResult {
    Terminate,
    DeleteKey(AppPeerPtr),
    SendInitiation(AppPeerPtr),
    SendRetransmission(AppPeerPtr),
    ReceivedMessage(usize, Endpoint),
}

pub enum KeyOutputReason {
    Exchanged,
    Stale,
}

#[derive(Debug)]
pub enum Endpoint {
    SocketBoundAddress(SocketBoundEndpoint),
    Discovery(HostPathDiscoveryEndpoint),
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::SocketBoundAddress(host) => write!(f, "{}", host),
            Endpoint::Discovery(host) => write!(f, "{}", host),
        }
    }
}

#[derive(Debug)]
pub struct SocketBoundEndpoint {
    socket: SocketPtr,
    addr: SocketAddr,
    bytes: (usize, [u8; SocketBoundEndpoint::BUFFER_SIZE]),
}

impl std::fmt::Display for SocketBoundEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.addr)
    }
}

impl SocketBoundEndpoint {
    const SOCKET_SIZE: usize = usize::BITS as usize / 8;
    const IPV6_SIZE: usize = 16;
    const PORT_SIZE: usize = 2;
    const SCOPE_ID_SIZE: usize = 4;
    const BUFFER_SIZE: usize = Self::SOCKET_SIZE + Self::IPV6_SIZE + Self::PORT_SIZE + Self::SCOPE_ID_SIZE;

    pub fn new(socket: SocketPtr, addr: SocketAddr) -> Self {
        let bytes = Self::to_bytes(&socket, &addr);
        Self { socket, addr, bytes }
    }

    fn to_bytes(socket: &SocketPtr, addr: &SocketAddr) -> (usize, [u8; Self::BUFFER_SIZE]) {
        let mut buf = [0u8; Self::BUFFER_SIZE];
        let addr_v6 = match addr {
            SocketAddr::V4(a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
            SocketAddr::V6(a) => *a,
        };
        let mut len: usize = 0;
        buf[len..len + Self::SOCKET_SIZE].copy_from_slice(&socket.0.to_be_bytes()); len += Self::SOCKET_SIZE;
        buf[len..len + Self::IPV6_SIZE].copy_from_slice(&addr_v6.ip().octets()); len += Self::IPV6_SIZE;
        buf[len..len + Self::PORT_SIZE].copy_from_slice(&addr_v6.port().to_be_bytes()); len += Self::PORT_SIZE;
        buf[len..len + Self::SCOPE_ID_SIZE].copy_from_slice(&addr_v6.scope_id().to_be_bytes()); len += Self::SCOPE_ID_SIZE;
        (len, buf)
    }
}

impl HostIdentification for SocketBoundEndpoint {
    fn encode(&self) -> &[u8] { &self.bytes.1[0..self.bytes.0] }
}

impl Endpoint {
    pub fn discovery_from_addresses(addresses: Vec<SocketAddr>) -> Self {
        Endpoint::Discovery(HostPathDiscoveryEndpoint::from_addresses(addresses))
    }

    pub fn discovery_from_hostname(hostname: String) -> anyhow::Result<Self> {
        Ok(Endpoint::Discovery(HostPathDiscoveryEndpoint::lookup(hostname)?))
    }

    pub fn discovery_from_multiple_sources(a: Option<&Endpoint>, b: Option<&Endpoint>) -> Option<Self> {
        let sources = match (a, b) {
            (Some(e), None) | (None, Some(e)) => e.addresses().iter().chain(&[]),
            (Some(e1), Some(e2)) => e1.addresses().iter().chain(e2.addresses()),
            (None, None) => return None,
        };
        let mut addrs = Vec::new();
        let mut dedup = std::collections::HashSet::new();
        for addr in sources {
            if dedup.insert(addr) { addrs.push(*addr); }
        }
        Some(Self::discovery_from_addresses(addrs))
    }

    pub fn send(&self, srv: &AppServer, buf: &[u8]) -> anyhow::Result<()> {
        match self {
            Endpoint::SocketBoundAddress(host) => host.socket.send_to(srv, buf, host.addr),
            Endpoint::Discovery(host) => host.send_scouting(srv, buf),
        }
    }

    fn addresses(&self) -> &[SocketAddr] {
        match self {
            Endpoint::SocketBoundAddress(host) => slice::from_ref(&host.addr),
            Endpoint::Discovery(host) => host.addresses(),
        }
    }
}

#[derive(Debug)]
pub struct HostPathDiscoveryEndpoint {
    scouting_state: Cell<(usize, usize)>,
    addresses: Vec<SocketAddr>,
}

impl std::fmt::Display for HostPathDiscoveryEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self.addresses)
    }
}

impl HostPathDiscoveryEndpoint {
    pub fn from_addresses(addresses: Vec<SocketAddr>) -> Self {
        Self { addresses, scouting_state: Cell::new((0, 0)) }
    }

    pub fn lookup(hostname: String) -> anyhow::Result<Self> {
        Ok(Self {
            addresses: ToSocketAddrs::to_socket_addrs(&hostname)?.collect(),
            scouting_state: Cell::new((0, 0)),
        })
    }

    pub fn addresses(&self) -> &[SocketAddr] { &self.addresses }

    fn insert_next_scout_offset(&self, srv: &AppServer, addr_no: usize, sock_no: usize) {
        self.scouting_state.set((
            (addr_no + 1) % self.addresses.len(),
            (sock_no + 1) % srv.sockets.len(),
        ));
    }

    pub fn send_scouting(&self, srv: &AppServer, buf: &[u8]) -> anyhow::Result<()> {
        let (addr_off, sock_off) = self.scouting_state.get();
        let mut addrs = self.addresses.iter().enumerate().cycle().skip(addr_off).take(self.addresses.len());
        let mut sockets = srv.sockets.iter().enumerate().cycle().skip(sock_off).take(srv.sockets.len());

        for (addr_no, addr) in addrs.by_ref() {
            for (sock_no, sock) in sockets.by_ref() {
                match sock.send_to(buf, *addr) {
                    Ok(_) => {
                        self.insert_next_scout_offset(srv, addr_no, sock_no);
                        return Ok(());
                    }
                    Err(e) => {
                        if !e.to_string().starts_with("Address family not supported") {
                            warn!("Socket #{} error sending to {}: {}", sock_no, addr, e);
                        }
                    }
                }
            }
        }
        bail!("All sockets failed to send scouting message.")
    }
}

impl AppServer {
    pub fn new(keypair: Option<(SSk, SPk)>, addrs: Vec<SocketAddr>, verbosity: Verbosity, test_helpers: Option<AppServerTest>) -> anyhow::Result<Self> {
        let mio_poll = mio::Poll::new()?;
        let events = mio::Events::with_capacity(EVENT_CAPACITY);
        let mut mio_token_dispenser = MioTokenDispenser::default();
        let mut io_source_index = HashMap::new();

        let signal_handler = attempt!({
            #[cfg(unix)] {
                let mut signals = signal_hook_mio::Signals::new(signal_hook::consts::TERM_SIGNALS.iter())?;
                let token = mio_token_dispenser.dispense();
                mio_poll.registry().register(&mut signals, token, Interest::READABLE)?;
                io_source_index.insert(token, AppServerIoSource::SignalHandler);
                Ok(NullDebug(signals))
            }
            #[cfg(not(unix))] { Ok(NullDebug(())) }
        })?;

        let mut sockets: Vec<mio::net::UdpSocket> = addrs.into_iter().map(mio::net::UdpSocket::bind).collect::<Result<_, _>>()?;

        if sockets.is_empty() {
            let mut try_bind = |title, binding| {
                match mio::net::UdpSocket::bind(binding) {
                    Ok(s) => { sockets.push(s); true }
                    Err(e) => { warn!("Could not bind {}: {}", title, e); false }
                }
            };
            if !try_bind("IPv6", ipv6_any_binding()) { try_bind("IPv4", ipv4_any_binding()); }
        }

        for (idx, socket) in sockets.iter_mut().enumerate() {
            let token = mio_token_dispenser.dispense();
            mio_poll.registry().register(socket, token, Interest::READABLE)?;
            io_source_index.insert(token, AppServerIoSource::Socket(idx));
        }

        let crypto_site = match keypair {
            Some((sk, pk)) => ConstructionSite::from_product(CryptoServer::new(sk, pk)),
            None => ConstructionSite::new(BuildCryptoServer::empty()),
        };

        Ok(Self {
            crypto_site, sockets, events, short_poll_queue: VecDeque::new(),
            performed_long_poll: false, io_source_index, mio_poll,
            mio_token_dispenser, signal_handler, brokers: BrokerStore::default(),
            peers: Vec::new(), verbosity, all_sockets_drained: false,
            under_load: DoSOperation::Normal, blocking_polls_count: 0,
            non_blocking_polls_count: 0, unpolled_count: 0,
            last_update_time: Instant::now(), test_helpers,
            #[cfg(feature = "experiment_api")]
            api_manager: crate::api::mio::MioManager::default(),
        })
    }

    pub fn crypto_server_mut(&mut self) -> anyhow::Result<&mut CryptoServer> {
        self.crypto_site.product_mut().context("Void")
    }

    pub fn crypto_server(&self) -> anyhow::Result<&CryptoServer> {
        self.crypto_site.product_ref().context("Void")
    }

    pub fn register_broker(&mut self, mut broker: Box<dyn WireguardBrokerMio<Error = anyhow::Error, MioError = anyhow::Error> + Send>) -> Result<BrokerStorePtr> {
        let ptr = Public::from_slice((self.brokers.store.len() as u64).as_bytes());
        let token = self.mio_token_dispenser.dispense();
        broker.register(self.mio_poll.registry(), token)?;
        self.brokers.store.insert(ptr, broker);
        self.io_source_index.insert(token, AppServerIoSource::PskBroker(ptr));
        Ok(BrokerStorePtr(ptr))
    }

    pub fn add_peer(&mut self, psk: Option<SymKey>, pk: SPk, outfile: Option<PathBuf>, broker_peer: Option<BrokerPeer>, hostname: Option<String>, protocol_version: ProtocolVersion, osk_domain_separator: OskDomainSeparator) -> anyhow::Result<AppPeerPtr> {
        let pn = self.crypto_server_mut()?.add_peer(psk, pk, protocol_version.into(), osk_domain_separator)?;
        let initial_endpoint = hostname.map(Endpoint::discovery_from_hostname).transpose()?;
        self.peers.push(AppPeer { outfile, broker_peer, initial_endpoint, current_endpoint: None });
        Ok(AppPeerPtr(pn.0))
    }

    pub fn event_loop(&mut self) -> anyhow::Result<()> {
        loop {
            if let Err(e) = self.event_loop_without_error_handling() {
                error!("Loop error: {e:?}");
                std::thread::sleep(Duration::from_millis(100));
            } else { return Ok(()); }
        }
    }

    pub fn event_loop_without_error_handling(&mut self) -> anyhow::Result<()> {
        let (mut rx, mut tx) = (MsgBuf::zero(), MsgBuf::zero());
        loop {
            let poll_result = self.poll(&mut *rx)?;
            match poll_result {
                AppPollResult::Terminate => return Ok(()),
                AppPollResult::SendInitiation(p) => {
                    if let Some(ep) = p.get_app(self).endpoint() {
                        let len = self.crypto_server_mut()?.initiate_handshake(p.lower(), &mut *tx)?;
                        ep.send(self, &tx[..len])?;
                    }
                }
                AppPollResult::SendRetransmission(p) => {
                    if let Some(ep) = p.get_app(self).endpoint() {
                        let len = self.crypto_server_mut()?.retransmit_handshake(p.lower(), &mut *tx)?;
                        ep.send(self, &tx[..len])?;
                    }
                }
                AppPollResult::DeleteKey(p) => {
                    self.output_key(p, KeyOutputReason::Stale, &SymKey::random())?;
                    let app = p.get_app_mut(self);
                    app.current_endpoint = Endpoint::discovery_from_multiple_sources(app.current_endpoint.as_ref(), app.initial_endpoint.as_ref());
                }
                AppPollResult::ReceivedMessage(len, ep) => {
                    let res = self.crypto_server_mut()?.handle_msg(&rx[..len], &mut *tx);
                    match res {
                        Ok(msg_res) => {
                            if let Some(l) = msg_res.resp { ep.send(self, &tx[..l])?; }
                            if let Some(peer_ptr) = msg_res.exchanged_with {
                                let ap = AppPeerPtr::lift(peer_ptr);
                                ap.get_app_mut(self).current_endpoint = Some(ep);
                                let osk = self.crypto_server_mut()?.osk(peer_ptr)?;
                                self.output_key(ap, KeyOutputReason::Exchanged, &osk)?;
                            }
                        }
                        Err(e) => if matches!(self.verbosity, Verbosity::Verbose) { warn!("Msg error: {e}"); }
                    }
                }
            }
        }
    }

    pub fn output_key(&mut self, peer: AppPeerPtr, why: KeyOutputReason, key: &SymKey) -> anyhow::Result<()> {
        let pid = peer.lower().get(self.crypto_server()?).pidt()?;
        if let Some(of) = peer.get_app(self).outfile.as_ref() {
            key.store_b64::<MAX_B64_KEY_SIZE, _>(of)?;
            let why_str = match why { KeyOutputReason::Exchanged => "exchanged", KeyOutputReason::Stale => "stale" };
            writeln!(stdout().lock(), "output-key peer {} key-file {of:?} {why_str}", pid.fmt_b64::<MAX_B64_PEER_ID_SIZE>())?;
        }
        peer.set_psk(self, key)?;
        Ok(())
    }

    pub fn poll(&mut self, rx_buf: &mut [u8]) -> anyhow::Result<AppPollResult> {
        loop {
            let crypto_poll = self.crypto_site.product_mut().map(|c| c.poll()).transpose()?;
            let timeout = match crypto_poll {
                Some(crate::protocol::PollResult::DeleteKey(p)) => return Ok(AppPollResult::DeleteKey(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::SendInitiation(p)) => return Ok(AppPollResult::SendInitiation(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::SendRetransmission(p)) => return Ok(AppPollResult::SendRetransmission(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::Sleep(t)) => t,
                None => crate::protocol::timing::UNENDING,
            };
            match self.try_recv(rx_buf, timeout)? {
                AppServerTryRecvResult::NetworkMessage(l, e) => return Ok(AppPollResult::ReceivedMessage(l, e)),
                AppServerTryRecvResult::Terminate => return Ok(AppPollResult::Terminate),
                AppServerTryRecvResult::None => {}
            }
        }
    }

    pub fn try_recv(&mut self, buf: &mut [u8], timeout: Timing) -> anyhow::Result<AppServerTryRecvResult> {
        let d = Duration::from_secs_f64(timeout);
        if self.short_poll_queue.is_empty() && self.all_sockets_drained {
            self.mio_poll.poll(&mut self.events, Some(d))?;
            for ev in self.events.iter() { self.short_poll_queue.push_back(ev.clone()); }
        }

        while let Some(ev) = self.short_poll_queue.pop_front() {
            if let Some(src) = self.io_source_index.get(&ev.token()) {
                match src {
                    AppServerIoSource::SignalHandler => return Ok(AppServerTryRecvResult::Terminate),
                    AppServerIoSource::Socket(idx) => {
                        if let Ok((n, addr)) = self.sockets[*idx].recv_from(buf) {
                            return Ok(AppServerTryRecvResult::NetworkMessage(n, Endpoint::SocketBoundAddress(SocketBoundEndpoint::new(SocketPtr(*idx), addr))));
                        }
                    }
                    AppServerIoSource::PskBroker(k) => { self.brokers.store.get_mut(k).unwrap().process_poll()?; }
                    _ => {}
                }
            }
        }
        self.all_sockets_drained = true;
        Ok(AppServerTryRecvResult::None)
    }
}
