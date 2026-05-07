//! This contains the bulk of the rosenpass server IO handling code whereas
//! the actual cryptographic code lives in the [crate::protocol] module

use std::collections::{HashMap, VecDeque};
use std::io::{stdout, ErrorKind, Write};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::{Duration, Instant};
use std::{cell::Cell, fmt::Debug, io, path::PathBuf, slice};

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

impl AppPeer {
    pub fn endpoint(&self) -> Option<Endpoint> {
        self.current_endpoint.clone().or_else(|| self.initial_endpoint.clone())
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
}

pub enum AppServerTryRecvResult {
    None,
    Terminate,
    NetworkMessage(usize, Endpoint),
}

const EVENT_CAPACITY: usize = 2048;

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
}

#[derive(Debug)]
pub enum AppPollResult {
    Terminate,
    DeleteKey(AppPeerPtr),
    SendInitiation(AppPeerPtr),
    SendRetransmission(AppPeerPtr),
    ReceivedMessage(usize, Endpoint),
}

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
    pub socket: SocketPtr,
    pub addr: SocketAddr,
}

impl std::fmt::Display for SocketBoundEndpoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { write!(f, "{}", self.addr) }
}

impl AppServer {
    pub fn new(keypair: Option<(SSk, SPk)>, addrs: Vec<SocketAddr>, verbosity: Verbosity, test_helpers: Option<AppServerTest>) -> anyhow::Result<Self> {
        let mio_poll = mio::Poll::new()?;
        let mut mio_token_dispenser = MioTokenDispenser::default();
        let mut io_source_index = HashMap::new();
        let mut sockets: Vec<mio::net::UdpSocket> = Vec::new();
        
        for addr in addrs {
            if let Ok(s) = mio::net::UdpSocket::bind(addr) { sockets.push(s); }
        }
        
        if sockets.is_empty() {
            if let Ok(s) = mio::net::UdpSocket::bind(ipv6_any_binding()) { sockets.push(s); }
            else if let Ok(s) = mio::net::UdpSocket::bind(ipv4_any_binding()) { sockets.push(s); }
        }

        for (idx, socket) in sockets.iter_mut().enumerate() {
            let token = mio_token_dispenser.dispense();
            mio_poll.registry().register(socket, token, Interest::READABLE)?;
            io_source_index.insert(token, AppServerIoSource::Socket(idx));
        }

        Ok(Self {
            crypto_site: match keypair {
                Some((sk, pk)) => ConstructionSite::from_product(CryptoServer::new(sk, pk)),
                None => ConstructionSite::new(BuildCryptoServer::empty()),
            },
            sockets, events: mio::Events::with_capacity(EVENT_CAPACITY),
            short_poll_queue: VecDeque::new(), performed_long_poll: false,
            io_source_index, mio_poll, mio_token_dispenser,
            brokers: BrokerStore::default(), peers: Vec::new(), verbosity,
            all_sockets_drained: false, under_load: DoSOperation::Normal,
            last_update_time: Instant::now(), test_helpers,
        })
    }

    pub fn crypto_server_mut(&mut self) -> anyhow::Result<&mut CryptoServer> {
        self.crypto_site.product_mut().context("Crypto server failure")
    }

    pub fn register_broker(&mut self, mut broker: Box<dyn WireguardBrokerMio<Error = anyhow::Error, MioError = anyhow::Error> + Send>) -> Result<BrokerStorePtr> {
        let id_raw = (self.brokers.store.len() as u64).to_be_bytes();
        let mut id = [0u8; BROKER_ID_BYTES];
        id.copy_from_slice(&id_raw);
        let ptr = Public::from_slice(&id);
        
        let token = self.mio_token_dispenser.dispense();
        broker.register(self.mio_poll.registry(), token)?;
        self.brokers.store.insert(ptr.clone(), broker); 
        self.io_source_index.insert(token, AppServerIoSource::PskBroker(ptr.clone()));
        Ok(BrokerStorePtr(ptr))
    }

    pub fn event_loop(&mut self) -> anyhow::Result<()> {
        let (mut rx, mut tx) = (MsgBuf::zero(), MsgBuf::zero());
        loop {
            match self.poll(&mut *rx)? {
                AppPollResult::Terminate => break Ok(()),
                AppPollResult::SendInitiation(p) => {
                    if let Some(ep) = self.peers[p.0].endpoint() {
                        let len = self.crypto_server_mut()?.initiate_handshake(p.lower(), &mut *tx)?;
                        let _ = self.send_to_endpoint(&ep, &tx[..len]);
                    }
                }
                AppPollResult::SendRetransmission(p) => {
                    if let Some(ep) = self.peers[p.0].endpoint() {
                        let len = self.crypto_server_mut()?.retransmit_handshake(p.lower(), &mut *tx)?;
                        let _ = self.send_to_endpoint(&ep, &tx[..len]);
                    }
                }
                AppPollResult::ReceivedMessage(len, ep) => {
                    if let Ok(msg_res) = self.crypto_server_mut()?.handle_msg(&rx[..len], &mut *tx) {
                        if let Some(l) = msg_res.resp { let _ = self.send_to_endpoint(&ep, &tx[..l]); }
                        if let Some(peer_ptr) = msg_res.exchanged_with {
                            let ap = AppPeerPtr::lift(peer_ptr);
                            self.peers[ap.0].current_endpoint = Some(ep);
                            if let Ok(osk) = self.crypto_server_mut()?.osk(peer_ptr) {
                                let _ = self.output_key(ap, &osk);
                            }
                        }
                    }
                }
                AppPollResult::DeleteKey(p) => { let _ = self.output_key(p, &SymKey::random()); }
            }
        }
    }

    pub fn output_key(&mut self, peer: AppPeerPtr, key: &SymKey) -> anyhow::Result<()> {
        if let Some(of) = self.peers[peer.0].outfile.as_ref() {
            let _ = key.store_b64::<MAX_B64_KEY_SIZE, _>(of);
        }
        if let Some(broker) = self.peers[peer.0].broker_peer.as_ref() {
            let config = broker.peer_cfg.create_config(key);
            if let Some(broker_obj) = self.brokers.store.get_mut(&broker.ptr().0) {
                let _ = broker_obj.set_psk(config);
            }
        }
        Ok(())
    }

    pub fn poll(&mut self, rx_buf: &mut [u8]) -> anyhow::Result<AppPollResult> {
        loop {
            if let Some(ref helpers) = self.test_helpers {
                if let Some(ref rx) = helpers.termination_handler {
                    if rx.try_recv().is_ok() { return Ok(AppPollResult::Terminate); }
                }
            }

            let res = self.crypto_site.product_mut().map(|c| c.poll()).transpose()?;
            let timeout = match res {
                Some(crate::protocol::PollResult::DeleteKey(p)) => return Ok(AppPollResult::DeleteKey(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::SendInitiation(p)) => return Ok(AppPollResult::SendInitiation(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::SendRetransmission(p)) => return Ok(AppPollResult::SendRetransmission(AppPeerPtr::lift(p))),
                Some(crate::protocol::PollResult::Sleep(t)) => t,
                _ => crate::protocol::timing::UNENDING,
            };

            if let Ok(AppServerTryRecvResult::NetworkMessage(l, e)) = self.try_recv(rx_buf, timeout) {
                return Ok(AppPollResult::ReceivedMessage(l, e));
            }
        }
    }

    pub fn try_recv(&mut self, buf: &mut [u8], timeout: Timing) -> anyhow::Result<AppServerTryRecvResult> {
        if self.short_poll_queue.is_empty() {
            let _ = self.mio_poll.poll(&mut self.events, Some(Duration::from_secs_f64(timeout)));
            for ev in self.events.iter() { self.short_poll_queue.push_back(ev.clone()); }
        }

        while let Some(ev) = self.short_poll_queue.pop_front() {
            if let Some(src) = self.io_source_index.get(&ev.token()) {
                match src {
                    AppServerIoSource::Socket(idx) => {
                        if let Ok((n, addr)) = self.sockets[*idx].recv_from(buf) {
                            return Ok(AppServerTryRecvResult::NetworkMessage(n, Endpoint::SocketBoundAddress(SocketBoundEndpoint { socket: SocketPtr(*idx), addr })));
                        }
                    }
                    AppServerIoSource::PskBroker(ptr) => {
                        // FIX: Corrected method name to 'process_poll' for Wireguard Broker/OBS connection
                        if let Some(broker) = self.brokers.store.get_mut(ptr) {
                            let _ = broker.process_poll(); 
                        }
                    }
                    _ => {}
                }
            }
        }
        Ok(AppServerTryRecvResult::None)
    }

    fn send_to_endpoint(&self, ep: &Endpoint, buf: &[u8]) -> Result<()> {
        match ep {
            Endpoint::SocketBoundAddress(sbe) => {
                if sbe.socket.0 < self.sockets.len() {
                    let _ = self.sockets[sbe.socket.0].send_to(buf, sbe.addr);
                }
            }
        }
        Ok(())
    }
}
