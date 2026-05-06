//! This contains the bulk of the rosenpass server IO handling code whereas
//! the actual cryptographic code lives in the [crate::protocol] module

use std::collections::{HashMap, VecDeque};
use std::io::Write;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{cell::Cell, fmt::Debug, path::PathBuf, slice};

use mio::{Interest, Token};
use anyhow::{bail, Context, Result};
use derive_builder::Builder;
use log::{error, info, warn};
use zerocopy::AsBytes;

use rosenpass_util::fmt::debug::NullDebug;
use rosenpass_util::{
    b64::B64Display, build::ConstructionSite, file::StoreValueB64,
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
    pub brokers: BrokerStore,
    pub peers: Vec<AppPeer>,
    pub verbosity: Verbosity,
    pub all_sockets_drained: bool,
    pub under_load: DoSOperation,
    pub last_update_time: Instant,
    pub test_helpers: Option<AppServerTest>,
}

#[derive(Debug, Copy, Clone)]
pub struct SocketPtr(pub usize);

#[derive(Debug, Copy, Clone)]
pub struct AppPeerPtr(pub usize);

impl AppPeerPtr {
    pub fn lift(p: PeerPtr) -> Self { Self(p.0) }
    pub fn lower(&self) -> PeerPtr { PeerPtr(self.0) }
    
    pub fn set_psk(&self, server: &mut AppServer, psk: &Secret<WG_KEY_LEN>) -> anyhow::Result<()> {
        if let Some(broker) = server.peers[self.0].broker_peer.as_ref() {
            let config = broker.peer_cfg.create_config(psk);
            let broker_obj = server.brokers.store.get_mut(&broker.ptr().0).context("Broker missing")?;
            broker_obj.set_psk(config)?;
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

pub enum KeyOutputReason { Exchanged, Stale }

#[derive(Debug, Clone)]
pub enum Endpoint {
    SocketBoundAddress(SocketBoundEndpoint),
}

impl std::fmt::Display for Endpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self { Endpoint::SocketBoundAddress(host) => write!(f, "{}", host) }
    }
}

#[derive(Debug, Clone)]
pub struct SocketBoundEndpoint {
    socket: SocketPtr,
    addr: SocketAddr,
}

impl std::fmt::Display for SocketBoundEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.addr) }
}

impl AppServer {
    pub fn new(keypair: Option<(SSk, SPk)>, addrs: Vec<SocketAddr>, verbosity: Verbosity, test_helpers: Option<AppServerTest>) -> anyhow::Result<Self> {
        let mio_poll = mio::Poll::new()?;
        let mut mio_token_dispenser = MioTokenDispenser::default();
        let mut sockets: Vec<mio::net::UdpSocket> = addrs.into_iter().map(mio::net::UdpSocket::bind).collect::<Result<_, _>>()?;
        
        if sockets.is_empty() {
            if let Ok(s) = mio::net::UdpSocket::bind(ipv6_any_binding()) { sockets.push(s); }
        }

        for socket in sockets.iter_mut() {
            mio_poll.registry().register(socket, mio_token_dispenser.dispense(), Interest::READABLE)?;
        }

        Ok(Self {
            crypto_site: match keypair {
                Some((sk, pk)) => ConstructionSite::from_product(CryptoServer::new(sk, pk)),
                None => ConstructionSite::new(BuildCryptoServer::empty()),
            },
            sockets, events: mio::Events::with_capacity(EVENT_CAPACITY),
            short_poll_queue: VecDeque::new(), performed_long_poll: false,
            io_source_index: HashMap::new(), mio_poll, mio_token_dispenser,
            brokers: BrokerStore::default(), peers: Vec::new(), verbosity,
            all_sockets_drained: false, under_load: DoSOperation::Normal,
            last_update_time: Instant::now(), test_helpers,
        })
    }

    pub fn crypto_server_mut(&mut self) -> anyhow::Result<&mut CryptoServer> {
        self.crypto_site.product_mut().context("Void")
    }

    pub fn event_loop(&mut self) -> anyhow::Result<()> {
        let (mut rx, mut tx) = (MsgBuf::zero(), MsgBuf::zero());
        loop {
            match self.poll(&mut *rx)? {
                AppPollResult::Terminate => return Ok(()),
                AppPollResult::SendInitiation(p) => {
                    // ফিক্স: Endpoint কে আগে ক্লোন করে বের করে আনা হয়েছে যাতে Borrow Conflict না হয়
                    let ep = self.peers[p.0].current_endpoint.clone()
                        .or_else(|| self.peers[p.0].initial_endpoint.clone());
                    
                    if let Some(endpoint) = ep {
                        let len = self.crypto_server_mut()?.initiate_handshake(p.lower(), &mut *tx)?;
                        self.send_to_endpoint(&endpoint, &tx[..len])?;
                    }
                }
                AppPollResult::SendRetransmission(p) => {
                    let ep = self.peers[p.0].current_endpoint.clone()
                        .or_else(|| self.peers[p.0].initial_endpoint.clone());
                        
                    if let Some(endpoint) = ep {
                        let len = self.crypto_server_mut()?.retransmit_handshake(p.lower(), &mut *tx)?;
                        self.send_to_endpoint(&endpoint, &tx[..len])?;
                    }
                }
                AppPollResult::ReceivedMessage(len, ep) => {
                    let msg_res = self.crypto_server_mut()?.handle_msg(&rx[..len], &mut *tx)?;
                    if let Some(l) = msg_res.resp { self.send_to_endpoint(&ep, &tx[..l])?; }
                    if let Some(peer_ptr) = msg_res.exchanged_with {
                        let ap = AppPeerPtr::lift(peer_ptr);
                        self.peers[ap.0].current_endpoint = Some(ep);
                        let osk = self.crypto_server_mut()?.osk(peer_ptr)?;
                        self.output_key(ap, &osk)?;
                    }
                }
                AppPollResult::DeleteKey(p) => {
                    self.output_key(p, &SymKey::random())?;
                }
            }
        }
    }

    fn send_to_endpoint(&self, ep: &Endpoint, buf: &[u8]) -> Result<()> {
        match ep {
            Endpoint::SocketBoundAddress(sbe) => {
                self.sockets[sbe.socket.0].send_to(buf, sbe.addr)?;
            }
        }
        Ok(())
    }

    pub fn output_key(&mut self, peer: AppPeerPtr, key: &SymKey) -> anyhow::Result<()> {
        if let Some(of) = self.peers[peer.0].outfile.as_ref() {
            key.store_b64::<MAX_B64_KEY_SIZE, _>(of)?;
        }
        peer.set_psk(self, key)?;
        Ok(())
    }

    pub fn poll(&mut self, rx_buf: &mut [u8]) -> anyhow::Result<AppPollResult> {
        loop {
            let res = self.crypto_site.product_mut().map(|c| c.poll()).transpose()?;
            let timeout = match res {
                Some(crate::protocol::PollResult::DeleteKey(p)) => return Ok(AppPollResult::DeleteKey(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::SendInitiation(p)) => return Ok(AppPollResult::SendInitiation(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::SendRetransmission(p)) => return Ok(AppPollResult::SendRetransmission(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::Sleep(t)) => t,
                None => crate::protocol::timing::UNENDING,
            };
            if let AppServerTryRecvResult::NetworkMessage(l, e) = self.try_recv(rx_buf, timeout)? {
                return Ok(AppPollResult::ReceivedMessage(l, e));
            }
        }
    }

    pub fn try_recv(&mut self, buf: &mut [u8], timeout: Timing) -> anyhow::Result<AppServerTryRecvResult> {
        if self.short_poll_queue.is_empty() {
            self.mio_poll.poll(&mut self.events, Some(Duration::from_secs_f64(timeout)))?;
            for ev in self.events.iter() { self.short_poll_queue.push_back(ev.clone()); }
        }
        while let Some(_ev) = self.short_poll_queue.pop_front() {
            for (idx, socket) in self.sockets.iter().enumerate() {
                if let Ok((n, addr)) = socket.recv_from(buf) {
                    return Ok(AppServerTryRecvResult::NetworkMessage(n, Endpoint::SocketBoundAddress(SocketBoundEndpoint { socket: SocketPtr(idx), addr })));
                }
            }
        }
        Ok(AppServerTryRecvResult::None)
    }
}
