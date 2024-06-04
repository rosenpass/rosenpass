//! Module containing the cryptographic protocol implementation
//!
//! # Overview
//!
//! The most important types in this module probably are [PollResult]
//! & [CryptoServer]. Once a [CryptoServer] is created, the server is
//! provided with new messages via the [CryptoServer::handle_msg] method.
//! The [CryptoServer::poll] method can be used to let the server work, which
//! will eventually yield a [PollResult]. Said [PollResult] contains
//! prescriptive activities to be carried out. [CryptoServer::osk] can than
//! be used to extract the shared key for two peers, once a key-exchange was
//! successful.
//!
//! TODO explain briefly the role of epki
//!
//! # Example Handshake
//!
//! This example illustrates a minimal setup for a key-exchange between two
//! [CryptoServer].
//!
//! ```
//! use rosenpass_cipher_traits::Kem;
//! use rosenpass_ciphers::kem::StaticKem;
//! use rosenpass::{
//!     protocol::{SSk, SPk, MsgBuf, PeerPtr, CryptoServer, SymKey},
//! };
//! # fn main() -> anyhow::Result<()> {
//!
//! // initialize secret and public key for peer a ...
//! let (mut peer_a_sk, mut peer_a_pk) = (SSk::zero(), SPk::zero());
//! StaticKem::keygen(peer_a_sk.secret_mut(), peer_a_pk.secret_mut())?;
//!
//! // ... and for peer b
//! let (mut peer_b_sk, mut peer_b_pk) = (SSk::zero(), SPk::zero());
//! StaticKem::keygen(peer_b_sk.secret_mut(), peer_b_pk.secret_mut())?;
//!
//! // initialize server and a pre-shared key
//! let psk = SymKey::random();
//! let mut a = CryptoServer::new(peer_a_sk, peer_a_pk.clone());
//! let mut b = CryptoServer::new(peer_b_sk, peer_b_pk.clone());
//!
//! // introduce peers to each other
//! a.add_peer(Some(psk.clone()), peer_b_pk)?;
//! b.add_peer(Some(psk), peer_a_pk)?;
//!
//! // declare buffers for message exchange
//! let (mut a_buf, mut b_buf) = (MsgBuf::zero(), MsgBuf::zero());
//!
//! // let a initiate a handshake
//! let mut maybe_len = Some(a.initiate_handshake(PeerPtr(0), a_buf.as_mut_slice())?);
//!
//! // let a and b communicate
//! while let Some(len) = maybe_len {
//!    maybe_len = b.handle_msg(&a_buf[..len], &mut b_buf[..])?.resp;
//!    std::mem::swap(&mut a, &mut b);
//!    std::mem::swap(&mut a_buf, &mut b_buf);
//! }
//!
//! // all done! Extract the shared keys and ensure they are identical
//! let a_key = a.osk(PeerPtr(0))?;
//! let b_key = b.osk(PeerPtr(0))?;
//! assert_eq!(a_key.secret(), b_key.secret(),
//!     "the key exchanged failed to establish a shared secret");
//! # Ok(())
//! # }
//! ```

use std::convert::Infallible;
use std::mem::size_of;
use std::{
    collections::hash_map::{
        Entry::{Occupied, Vacant},
        HashMap,
    },
    fmt::Display,
};

use anyhow::{bail, ensure, Context, Result};
use rand::Fill as Randomize;

use memoffset::span_of;
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::hash_domain::{SecretHashDomain, SecretHashDomainNamespace};
use rosenpass_ciphers::kem::{EphemeralKem, StaticKem};
use rosenpass_ciphers::{aead, xaead, KEY_LEN};
use rosenpass_constant_time as constant_time;
use rosenpass_secret_memory::{Public, Secret};
use rosenpass_util::{cat, mem::cpy_min, ord::max_usize, time::Timebase};
use zerocopy::{AsBytes, FromBytes, Ref};

use crate::{hash_domains, msgs::*, RosenpassError};

// CONSTANTS & SETTINGS //////////////////////////

/// Size required to fit any message in binary form
pub const RTX_BUFFER_SIZE: usize = max_usize(
    size_of::<Envelope<InitHello>>(),
    size_of::<Envelope<InitConf>>(),
);

/// A type for time, e.g. for backoff before re-tries
pub type Timing = f64;

/// Before Common Era (or more practically: Definitely so old it needs refreshing)
///
/// Using this instead of Timing::MIN or Timing::INFINITY to avoid floating
/// point math weirdness.
pub const BCE: Timing = -3600.0 * 24.0 * 356.0 * 10_000.0;

// Actually it's eight hours; This is intentional to avoid weirdness
// regarding unexpectedly large numbers in system APIs as this is < i16::MAX
pub const UNENDING: Timing = 3600.0 * 8.0;

// From the wireguard paper; rekey every two minutes,
// discard the key if no rekey is achieved within three
pub const REKEY_AFTER_TIME_RESPONDER: Timing = 120.0;
pub const REKEY_AFTER_TIME_INITIATOR: Timing = 130.0;
pub const REJECT_AFTER_TIME: Timing = 180.0;

// From the wireguard paper; "under no circumstances send an initiation message more than once every 5 seconds"
pub const REKEY_TIMEOUT: Timing = 5.0;

// Cookie Secret `cookie_secret` in the whitepaper
pub const COOKIE_SECRET_LEN: usize = MAC_SIZE;
pub const COOKIE_SECRET_EPOCH: Timing = 120.0;

// Cookie value len in whitepaper
pub const COOKIE_VALUE_LEN: usize = MAC_SIZE;
// Peer `cookie_value` validity
pub const PEER_COOKIE_VALUE_EPOCH: Timing = 120.0;

// Seconds until the biscuit key is changed; we issue biscuits
// using one biscuit key for one epoch and store the biscuit for
// decryption for a second epoch
pub const BISCUIT_EPOCH: Timing = 300.0;

// Retransmission pub constants; will retransmit for up to _ABORT ms; starting with a delay of
// _DELAY_BEG ms and increasing the delay exponentially by a factor of
// _DELAY_GROWTH up to _DELAY_END. An additional jitter factor of ±_DELAY_JITTER
// is added.
pub const RETRANSMIT_ABORT: Timing = 120.0;
pub const RETRANSMIT_DELAY_GROWTH: Timing = 2.0;
pub const RETRANSMIT_DELAY_BEGIN: Timing = 0.5;
pub const RETRANSMIT_DELAY_END: Timing = 10.0;
pub const RETRANSMIT_DELAY_JITTER: Timing = 0.5;

pub const EVENT_GRACE: Timing = 0.0025;

// UTILITY FUNCTIONS /////////////////////////////

// Event handling: For an event at T we sleep for T-now
// but we act on the event starting at T-EVENT_GRACE already
// to avoid sleeping for very short periods. This also avoids
// busy loop in case the sleep subsystem is imprecise. Our timing
// is therefor generally accurate up to ±2∙EVENT_GRACE
pub fn has_happened(ev: Timing, now: Timing) -> bool {
    (ev - now) < EVENT_GRACE
}

// DATA STRUCTURES & BASIC TRAITS & ACCESSORS ////

pub type SPk = Secret<{ StaticKem::PK_LEN }>; // Just Secret<> instead of Public<> so it gets allocated on the heap
pub type SSk = Secret<{ StaticKem::SK_LEN }>;
pub type EPk = Public<{ EphemeralKem::PK_LEN }>;
pub type ESk = Secret<{ EphemeralKem::SK_LEN }>;

pub type SymKey = Secret<KEY_LEN>;
pub type SymHash = Public<KEY_LEN>;

pub type PeerId = Public<KEY_LEN>;
pub type SessionId = Public<SESSION_ID_LEN>;
pub type BiscuitId = Public<BISCUIT_ID_LEN>;

pub type XAEADNonce = Public<{ xaead::NONCE_LEN }>;

pub type MsgBuf = Public<MAX_MESSAGE_LEN>;

pub type PeerNo = usize;

/// Implementation of the cryptographic protocol
///
/// The scope of this is:
///
/// - logical protocol flow
/// - timeout handling
/// - key exchange
///
/// Not in scope of this struct:
///
/// - handling of external IO (like sockets etc.)
#[derive(Debug)]
pub struct CryptoServer {
    pub timebase: Timebase,

    // Server Crypto
    pub sskm: SSk,
    pub spkm: SPk,
    pub biscuit_ctr: BiscuitId,
    pub biscuit_keys: [BiscuitKey; 2],

    // Peer/Handshake DB
    pub peers: Vec<Peer>,
    pub index: HashMap<IndexKey, PeerNo>,

    // Tick handling
    pub peer_poll_off: usize,

    // Random state which changes every COOKIE_SECRET_EPOCH seconds
    pub cookie_secrets: [CookieSecret; 2],
}

/// Container for storing cookie types: Biscuit, CookieSecret, CookieValue
#[derive(Debug)]
pub struct CookieStore<const N: usize> {
    pub created_at: Timing,
    pub value: Secret<N>,
}

/// Stores cookie secret, which is used to create a rotating the cookie value
pub type CookieSecret = CookieStore<COOKIE_SECRET_LEN>;

/// A Biscuit is like a fancy cookie. To avoid state disruption attacks,
/// the responder doesn't store state. Instead the state is stored in a
/// Biscuit, that is encrypted using the [BiscuitKey] which is only known to
/// the Responder. Thus secrecy of the Responder state is not violated, still
/// the responder can avoid storing this state.
pub type BiscuitKey = CookieStore<KEY_LEN>;

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum IndexKey {
    Peer(PeerId),
    Sid(SessionId),
}

#[derive(Debug)]
pub struct Peer {
    pub psk: SymKey,
    pub spkt: SPk,
    pub biscuit_used: BiscuitId,
    pub session: Option<Session>,
    pub handshake: Option<InitiatorHandshake>,
    pub initiation_requested: bool,
}

impl Peer {
    pub fn zero() -> Self {
        Self {
            psk: SymKey::zero(),
            spkt: SPk::zero(),
            biscuit_used: BiscuitId::zero(),
            session: None,
            initiation_requested: false,
            handshake: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeState {
    /// Session ID of Initiator
    pub sidi: SessionId,
    /// Session ID of Responder
    pub sidr: SessionId,
    /// Chaining Key
    pub ck: SecretHashDomainNamespace, // TODO: We should probably add an abstr
}

#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Copy, Clone)]
pub enum HandshakeRole {
    Initiator,
    Responder,
}

impl HandshakeRole {
    pub fn is_initiator(&self) -> bool {
        match *self {
            HandshakeRole::Initiator => true,
            HandshakeRole::Responder => false,
        }
    }
}

#[derive(Copy, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum HandshakeStateMachine {
    #[default]
    RespHello,
    RespConf,
}

#[derive(Debug)]
pub struct InitiatorHandshake {
    pub created_at: Timing,
    pub next: HandshakeStateMachine,
    pub core: HandshakeState,
    /// Ephemeral Secret Key of Initiator
    pub eski: ESk,
    /// Ephemeral Public Key of Initiator
    pub epki: EPk,

    // Retransmission
    // TODO: Ensure that this is correct by typing
    pub tx_at: Timing,
    pub tx_retry_at: Timing,
    pub tx_count: usize,
    pub tx_len: usize,
    pub tx_buf: MsgBuf,

    // Cookie storage for retransmission, expires PEER_COOKIE_VALUE_EPOCH seconds after creation
    pub cookie_value: CookieStore<COOKIE_VALUE_LEN>,
}

#[derive(Debug)]
pub struct Session {
    // Metadata
    pub created_at: Timing,
    pub sidm: SessionId,
    pub sidt: SessionId,
    pub handshake_role: HandshakeRole,
    // Crypto
    pub ck: SecretHashDomainNamespace,
    /// Key for Transmission ("transmission key mine")
    pub txkm: SymKey,
    /// Key for Reception ("transmission key theirs")
    pub txkt: SymKey,
    /// Nonce for Transmission ("transmission nonce mine")
    pub txnm: u64,
    /// Nonce for Reception ("transmission nonce theirs")
    pub txnt: u64,
}

/// Lifecycle of a Secret
///
/// The order implies the readiness for usage of a secret, the highest/biggest
/// variant ([Lifecycle::Young]) is the most preferable one in a class of
/// equal-role secrets.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Lifecycle {
    /// Not even generated
    Void = 0,
    /// Secret must be zeroized, disposal advised
    Dead,
    /// Soon to be dead: the secret might be used for receiving
    /// data, but must not be used for future sending
    Retired,
    /// The secret might be used unconditionally
    Young,
}

/// Implemented for information (secret and public) that has an expire date
trait Mortal {
    /// Time of creation, when [Lifecycle::Void] -> [Lifecycle::Young]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing>;
    /// The time where [Lifecycle::Young] -> [Lifecycle::Retired]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing>;
    /// The time where [Lifecycle::Retired] -> [Lifecycle::Dead]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing>;
}

// BUSINESS LOGIC DATA STRUCTURES ////////////////

/// Valid index to [CryptoServer::peers]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PeerPtr(pub usize);

/// Valid index to [CryptoServer::peers]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IniHsPtr(pub usize);

/// Valid index to [CryptoServer::peers]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SessionPtr(pub usize);

/// Valid index to [CryptoServer::biscuit_keys]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BiscuitKeyPtr(pub usize);

/// Valid index to [CryptoServer::cookie_secrets] cookie value
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ServerCookieSecretPtr(pub usize);

/// Valid index to [CryptoServer::peers] cookie value
pub struct PeerCookieValuePtr(usize);

impl PeerPtr {
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a Peer {
        &srv.peers[self.0]
    }

    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut Peer {
        &mut srv.peers[self.0]
    }

    pub fn session(&self) -> SessionPtr {
        SessionPtr(self.0)
    }

    pub fn hs(&self) -> IniHsPtr {
        IniHsPtr(self.0)
    }

    pub fn cv(&self) -> PeerCookieValuePtr {
        PeerCookieValuePtr(self.0)
    }
}

impl IniHsPtr {
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a Option<InitiatorHandshake> {
        &srv.peers[self.0].handshake
    }

    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut Option<InitiatorHandshake> {
        &mut srv.peers[self.0].handshake
    }

    pub fn peer(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    pub fn insert<'a>(
        &self,
        srv: &'a mut CryptoServer,
        hs: InitiatorHandshake,
    ) -> Result<&'a mut InitiatorHandshake> {
        srv.register_session(hs.core.sidi, self.peer())?;
        self.take(srv);
        self.peer().get_mut(srv).initiation_requested = false;
        Ok(self.peer().get_mut(srv).handshake.insert(hs))
    }

    pub fn take(&self, srv: &mut CryptoServer) -> Option<InitiatorHandshake> {
        let r = self.peer().get_mut(srv).handshake.take();
        if let Some(ref stale) = r {
            srv.unregister_session_if_vacant(stale.core.sidi, self.peer());
        }
        r
    }
}

impl SessionPtr {
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a Option<Session> {
        &srv.peers[self.0].session
    }

    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut Option<Session> {
        &mut srv.peers[self.0].session
    }

    pub fn peer(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    pub fn insert<'a>(&self, srv: &'a mut CryptoServer, ses: Session) -> Result<&'a mut Session> {
        self.take(srv);
        srv.register_session(ses.sidm, self.peer())?;
        Ok(self.peer().get_mut(srv).session.insert(ses))
    }

    pub fn take(&self, srv: &mut CryptoServer) -> Option<Session> {
        let r = self.peer().get_mut(srv).session.take();
        if let Some(ref stale) = r {
            srv.unregister_session_if_vacant(stale.sidm, self.peer());
        }
        r
    }
}

impl BiscuitKeyPtr {
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a BiscuitKey {
        &srv.biscuit_keys[self.0]
    }

    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut BiscuitKey {
        &mut srv.biscuit_keys[self.0]
    }
}

impl ServerCookieSecretPtr {
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a CookieSecret {
        &srv.cookie_secrets[self.0]
    }

    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut CookieSecret {
        &mut srv.cookie_secrets[self.0]
    }
}

impl PeerCookieValuePtr {
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> Option<&'a CookieStore<COOKIE_SECRET_LEN>> {
        srv.peers[self.0]
            .handshake
            .as_ref()
            .map(|v| &v.cookie_value)
    }

    pub fn update_mut<'a>(&self, srv: &'a mut CryptoServer) -> Option<&'a mut [u8]> {
        let timebase = srv.timebase.clone();

        if let Some(cs) = PeerPtr(self.0)
            .hs()
            .get_mut(srv)
            .as_mut()
            .map(|v| &mut v.cookie_value)
        {
            cs.created_at = timebase.now();
            Some(cs.value.secret_mut())
        } else {
            None
        }
    }
}

// DATABASE //////////////////////////////////////

impl CryptoServer {
    /// Initiate a new [CryptoServer] based on a secret key (`sk`) and a public key
    /// (`pk`)
    pub fn new(sk: SSk, pk: SPk) -> CryptoServer {
        let tb = Timebase::default();
        CryptoServer {
            sskm: sk,
            spkm: pk,

            // Defaults
            timebase: tb,
            biscuit_ctr: BiscuitId::new([1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), // 1, LSB
            biscuit_keys: [CookieStore::new(), CookieStore::new()],
            peers: Vec::new(),
            index: HashMap::new(),
            peer_poll_off: 0,
            cookie_secrets: [CookieStore::new(), CookieStore::new()],
        }
    }

    /// Iterate over the many (2) biscuit keys
    pub fn biscuit_key_ptrs(&self) -> impl Iterator<Item = BiscuitKeyPtr> {
        (0..self.biscuit_keys.len()).map(BiscuitKeyPtr)
    }

    pub fn cookie_secret_ptrs(&self) -> impl Iterator<Item = ServerCookieSecretPtr> {
        (0..self.cookie_secrets.len()).map(ServerCookieSecretPtr)
    }

    #[rustfmt::skip]
    pub fn pidm(&self) -> Result<PeerId> {
        Ok(Public::new(
            hash_domains::peerid()?
                .mix(self.spkm.secret())?
                .into_value()))
    }

    /// Iterate over all peers, starting with the `n`th peer, wrapping at the
    /// end of the peers vec so that also all peers from index 0 to `n - 1` are
    /// yielded
    pub fn peer_ptrs_off(&self, n: usize) -> impl Iterator<Item = PeerPtr> {
        let l = self.peers.len();
        (0..l).map(move |i| PeerPtr((i + n) % l))
    }

    /// Add a peer with an optional pre shared key (`psk`) and its public key (`pk`)
    pub fn add_peer(&mut self, psk: Option<SymKey>, pk: SPk) -> Result<PeerPtr> {
        let peer = Peer {
            psk: psk.unwrap_or_else(SymKey::zero),
            spkt: pk,
            biscuit_used: BiscuitId::zero(),
            session: None,
            handshake: None,
            initiation_requested: false,
        };
        let peerid = peer.pidt()?;
        let peerno = self.peers.len();
        match self.index.entry(IndexKey::Peer(peerid)) {
            Occupied(_) => bail!(
                "Cannot insert peer with id {:?}; peer with this id already registered.",
                peerid
            ),
            Vacant(e) => e.insert(peerno),
        };
        self.peers.push(peer);
        Ok(PeerPtr(peerno))
    }

    /// Register a new session (during a successful handshake, persisting longer
    /// than the handshake). Might return an error on session id collision
    pub fn register_session(&mut self, id: SessionId, peer: PeerPtr) -> Result<()> {
        match self.index.entry(IndexKey::Sid(id)) {
            Occupied(p) if PeerPtr(*p.get()) == peer => {} // Already registered
            Occupied(_) => bail!("Cannot insert session with id {:?}; id is in use.", id),
            Vacant(e) => {
                e.insert(peer.0);
            }
        };
        Ok(())
    }

    pub fn unregister_session(&mut self, id: SessionId) {
        self.index.remove(&IndexKey::Sid(id));
    }

    /// Remove the given session if it is neither an active session nor in
    /// handshake phase
    pub fn unregister_session_if_vacant(&mut self, id: SessionId, peer: PeerPtr) {
        match (peer.session().get(self), peer.hs().get(self)) {
            (Some(ses), _) if ses.sidm == id => {}    /* nop */
            (_, Some(hs)) if hs.core.sidi == id => {} /* nop */
            _ => self.unregister_session(id),
        };
    }

    pub fn find_peer(&self, id: PeerId) -> Option<PeerPtr> {
        self.index.get(&IndexKey::Peer(id)).map(|no| PeerPtr(*no))
    }

    // lookup_session in whitepaper
    pub fn lookup_handshake(&self, id: SessionId) -> Option<IniHsPtr> {
        self.index
            .get(&IndexKey::Sid(id)) // lookup the session in the index
            .map(|no| IniHsPtr(*no)) // convert to peer pointer
            .filter(|hsptr| {
                hsptr
                    .get(self) // lookup in the server
                    .as_ref()
                    .map(|hs| hs.core.sidi == id) // check that handshake id matches as well
                    .unwrap_or(false) // it didn't match?!
            })
    }

    // also lookup_session in the whitepaper
    pub fn lookup_session(&self, id: SessionId) -> Option<SessionPtr> {
        self.index
            .get(&IndexKey::Sid(id))
            .map(|no| SessionPtr(*no))
            .filter(|sptr| {
                sptr.get(self)
                    .as_ref()
                    .map(|ses| ses.sidm == id)
                    .unwrap_or(false)
            })
    }

    /// Swap the biscuit keys, also advancing both biscuit key's mortality
    pub fn active_biscuit_key(&mut self) -> BiscuitKeyPtr {
        let (a, b) = (BiscuitKeyPtr(0), BiscuitKeyPtr(1));
        let (t, u) = (a.get(self).created_at, b.get(self).created_at);

        // Return the youngest but only if it's youthful
        // first being returned in case of a tie
        let r = if t >= u { a } else { b };
        if r.lifecycle(self) == Lifecycle::Young {
            return r;
        }

        // Reap the oldest biscuit key and spawn a new young one otherwise
        // last one being reaped in case of a tie
        let r = if t < u { a } else { b };
        let tb = self.timebase.clone();
        r.get_mut(self).randomize(&tb);
        r
    }

    // Return cookie secrets in order of youthfulness (youngest first)
    pub fn active_or_retired_cookie_secrets(&mut self) -> [Option<ServerCookieSecretPtr>; 2] {
        let (a, b) = (ServerCookieSecretPtr(0), ServerCookieSecretPtr(1));
        let (t, u) = (a.get(self).created_at, b.get(self).created_at);
        let mut return_arr = [None, None];
        let mut index_top = 0;

        // Add the youngest but only if it's youthful first (being added first in case of a tie)
        let (young, old) = if t >= u { (a, b) } else { (b, a) };
        if young.lifecycle(self) == Lifecycle::Young || young.lifecycle(self) == Lifecycle::Retired
        {
            return_arr[index_top] = Some(young);
            index_top += 1;
        }

        if old.lifecycle(self) == Lifecycle::Young || old.lifecycle(self) == Lifecycle::Retired {
            return_arr[index_top] = Some(old);
            index_top += 1;
        }

        if index_top == 0 {
            // Reap the oldest biscuit key and spawn a new young one
            let tb = self.timebase.clone();
            old.get_mut(self).randomize(&tb);
            return_arr[index_top] = Some(old);
        }

        return_arr
    }
}

impl Peer {
    pub fn new(psk: SymKey, pk: SPk) -> Peer {
        Peer {
            psk,
            spkt: pk,
            biscuit_used: BiscuitId::zero(),
            session: None,
            handshake: None,
            initiation_requested: false,
        }
    }

    #[rustfmt::skip]
    pub fn pidt(&self) -> Result<PeerId> {
        Ok(Public::new(
            hash_domains::peerid()?
                .mix(self.spkt.secret())?
                .into_value()))
    }
}

impl Session {
    pub fn zero() -> Self {
        Self {
            created_at: 0.0,
            sidm: SessionId::zero(),
            sidt: SessionId::zero(),
            handshake_role: HandshakeRole::Initiator,
            ck: SecretHashDomain::zero().dup(),
            txkm: SymKey::zero(),
            txkt: SymKey::zero(),
            txnm: 0,
            txnt: 0,
        }
    }
}

// COOKIE STORE ///////////////////////////////////
impl<const N: usize> CookieStore<N> {
    // new creates a random value, that might be counterintuitive for a Default
    // impl
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            created_at: BCE,
            value: Secret::<N>::random(),
        }
    }

    pub fn erase(&mut self) {
        self.value.randomize();
        self.created_at = BCE;
    }

    pub fn randomize(&mut self, tb: &Timebase) {
        self.value.randomize();
        self.created_at = tb.now();
    }

    pub fn update(&mut self, tb: &Timebase, value: &[u8]) {
        self.value.secret_mut().copy_from_slice(value);
        self.created_at = tb.now();
    }
}

// LIFECYCLE MANAGEMENT //////////////////////////

impl Mortal for IniHsPtr {
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.get(srv).as_ref().map(|hs| hs.created_at)
    }

    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.die_at(srv)
    }

    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + REJECT_AFTER_TIME)
    }
}

impl Mortal for SessionPtr {
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.get(srv).as_ref().map(|p| p.created_at)
    }

    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        // If we were the initiator, wait an extra ten seconds to avoid
        // both parties starting the handshake at the same time. In most situations
        // this should provide ample time for the other party to perform a
        // complete handshake before this peer starts another handshake.
        // This also has the peers going back and forth taking the initiator role
        // and responder role.
        use HandshakeRole::*;
        self.get(srv).as_ref().map(|p| {
            let wait = match p.handshake_role {
                Initiator => REKEY_AFTER_TIME_INITIATOR,
                Responder => REKEY_AFTER_TIME_RESPONDER,
            };
            p.created_at + wait
        })
    }

    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + REJECT_AFTER_TIME)
    }
}

impl Mortal for BiscuitKeyPtr {
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        let t = self.get(srv).created_at;
        if t < 0.0 {
            None
        } else {
            Some(t)
        }
    }

    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + BISCUIT_EPOCH)
    }

    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.retire_at(srv).map(|t| t + BISCUIT_EPOCH)
    }
}

impl Mortal for ServerCookieSecretPtr {
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        let t = self.get(srv).created_at;
        if t < 0.0 {
            None
        } else {
            Some(t)
        }
    }
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + COOKIE_SECRET_EPOCH)
    }
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.retire_at(srv).map(|t| t + COOKIE_SECRET_EPOCH)
    }
}

impl Mortal for PeerCookieValuePtr {
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        if let Some(cs) = self.get(srv) {
            if cs.created_at < 0.0 {
                return None;
            }
            Some(cs.created_at)
        } else {
            None
        }
    }

    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.die_at(srv)
    }

    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + PEER_COOKIE_VALUE_EPOCH)
    }
}

/// Trait extension to the [Mortal] Trait, that enables nicer access to timing
/// information
trait MortalExt: Mortal {
    fn life_left(&self, srv: &CryptoServer) -> Option<Timing>;
    fn youth_left(&self, srv: &CryptoServer) -> Option<Timing>;
    fn lifecycle(&self, srv: &CryptoServer) -> Lifecycle;
}

impl<T: Mortal> MortalExt for T {
    fn life_left(&self, srv: &CryptoServer) -> Option<Timing> {
        self.die_at(srv).map(|t| t - srv.timebase.now())
    }

    fn youth_left(&self, srv: &CryptoServer) -> Option<Timing> {
        self.retire_at(srv).map(|t| t - srv.timebase.now())
    }

    fn lifecycle(&self, srv: &CryptoServer) -> Lifecycle {
        match (self.youth_left(srv), self.life_left(srv)) {
            (_, Some(t)) if has_happened(t, 0.0) => Lifecycle::Dead,
            (Some(t), _) if has_happened(t, 0.0) => Lifecycle::Retired,
            (Some(_), Some(_)) => Lifecycle::Young,
            _ => Lifecycle::Void,
        }
    }
}

// MESSAGE HANDLING //////////////////////////////

impl CryptoServer {
    /// Initiate a new handshake, put it to the `tx_buf` __and__ to the
    /// retransmission storage
    // NOTE retransmission? yes if initiator, no if responder
    // TODO remove unnecessary copying between global tx_buf and per-peer buf
    // TODO move retransmission storage to io server
    pub fn initiate_handshake(&mut self, peer: PeerPtr, tx_buf: &mut [u8]) -> Result<usize> {
        // Envelope::<InitHello>::default(); // TODO
        let mut msg = truncating_cast_into::<Envelope<InitHello>>(tx_buf)?;
        self.handle_initiation(peer, &mut msg.payload)?;
        let len = self.seal_and_commit_msg(peer, MsgType::InitHello, &mut msg)?;
        peer.hs()
            .store_msg_for_retransmission(self, msg.as_bytes())?;
        Ok(len)
    }
}

#[derive(Debug)]
pub struct HandleMsgResult {
    pub exchanged_with: Option<PeerPtr>,
    pub resp: Option<usize>,
}

/// Trait for host identification types
pub trait HostIdentification: Display {
    // Byte slice representing the host identification encoding
    fn encode(&self) -> &[u8];
}

impl CryptoServer {
    /// Process a message under load
    /// This is one of the main entry point for the protocol.
    /// Keeps track of messages processed, and qualifies messages using
    /// cookie based DoS mitigation.
    /// If recieving a InitHello message, it dispatches message for further processing
    /// to `process_msg` handler if cookie is valid otherwise sends a cookie reply
    /// message for sender to process and verify for messages part of the handshake phase
    /// Directly processes InitConf messages.
    /// Bails on messages sent by responder and non-handshake messages.

    pub fn handle_msg_under_load<H: HostIdentification>(
        &mut self,
        rx_buf: &[u8],
        tx_buf: &mut [u8],
        host_identification: &H,
    ) -> Result<HandleMsgResult> {
        let mut active_cookie_value: Option<[u8; COOKIE_SIZE]> = None;
        let mut rx_cookie = [0u8; COOKIE_SIZE];
        let mut rx_mac = [0u8; MAC_SIZE];
        let mut rx_sid = [0u8; 4];
        let msg_type: Result<MsgType, _> = rx_buf[0].try_into();
        match msg_type {
            Ok(MsgType::InitConf) => {
                log::debug!(
                    "Rx {:?} from {} under load, skip cookie validation",
                    msg_type,
                    host_identification
                );
                return self.handle_msg(rx_buf, tx_buf);
            }
            Ok(MsgType::InitHello) => {
                //Process message (continued below)
            }
            _ => {
                bail!(
                    "Rx {:?} from {} is not processed under load",
                    msg_type,
                    host_identification
                );
            }
        }

        for cookie_secret in self.active_or_retired_cookie_secrets() {
            if let Some(cookie_secret) = cookie_secret {
                let cookie_secret = cookie_secret.get(self).value.secret();
                let mut cookie_value = [0u8; 16];
                cookie_value.copy_from_slice(
                    &hash_domains::cookie_value()?
                        .mix(cookie_secret)?
                        .mix(host_identification.encode())?
                        .into_value()[..16],
                );

                //Most recently filled value is active cookie value
                if active_cookie_value.is_none() {
                    active_cookie_value = Some(cookie_value);
                }

                let mut expected = [0u8; COOKIE_SIZE];

                let msg_in = Ref::<&[u8], Envelope<InitHello>>::new(rx_buf)
                    .ok_or(RosenpassError::BufferSizeMismatch)?;
                expected.copy_from_slice(
                    &hash_domains::cookie()?
                        .mix(&cookie_value)?
                        .mix(&msg_in.as_bytes()[span_of!(Envelope<InitHello>, msg_type..cookie)])?
                        .into_value()[..16],
                );

                rx_cookie.copy_from_slice(&msg_in.cookie);
                rx_mac.copy_from_slice(&msg_in.mac);
                rx_sid.copy_from_slice(&msg_in.payload.sidi);

                //If valid cookie is found, process message
                if constant_time::memcmp(&rx_cookie, &expected) {
                    log::debug!(
                        "Rx {:?} from {} under load, valid cookie",
                        msg_type,
                        host_identification
                    );
                    let result = self.handle_msg(rx_buf, tx_buf)?;
                    return Ok(result);
                }
            } else {
                break;
            }
        }

        //Otherwise send cookie reply
        if active_cookie_value.is_none() {
            bail!("No active cookie value found");
        }

        log::debug!(
            "Rx {:?} from {} under load, tx cookie reply message",
            msg_type,
            host_identification
        );

        let cookie_value = active_cookie_value.unwrap();
        let cookie_key = hash_domains::cookie_key()?
            .mix(self.spkm.secret())?
            .into_value();

        let mut msg_out = truncating_cast_into::<CookieReply>(tx_buf)?;

        let nonce = XAEADNonce::random();

        msg_out.inner.msg_type = MsgType::CookieReply.into();
        msg_out.inner.sid = rx_sid;

        xaead::encrypt(
            &mut msg_out.inner.cookie_encrypted[..],
            &cookie_key,
            &nonce.value,
            &rx_mac,
            &cookie_value,
        )?;

        msg_out
            .padding
            .try_fill(&mut rosenpass_secret_memory::rand::rng())
            .unwrap();

        // length of the response
        let _len = Some(size_of::<CookieReply>());

        Ok(HandleMsgResult {
            exchanged_with: None,
            resp: Some(size_of::<CookieReply>()),
        })
    }

    /// Handle an incoming message
    /// This is one of the main entry point for the protocol.
    ///
    /// # Overview
    ///
    /// The response is only dependent on the incoming message, thus this
    /// function is called regardless of whether the the the calling context is
    /// an initiator, a responder or both. The flow of is as follows:
    ///
    /// 1. check incoming message for valid [MsgType]
    /// 2. check that the seal is intact, e.g. that the message is
    ///    authenticated
    /// 3. call the respective handler function for this message (for example
    ///    [Self::handle_init_hello])
    /// 4. if the protocol foresees a response to this message, generate one
    /// 5. seal the response with cryptographic authentication
    /// 6. if the response is a ResponseHello, store the sealed response for
    ///    further retransmission
    /// 7. return some peer pointer if the exchange completed with this message
    /// 8. return the length of the response generated
    ///
    /// This is the sequence of a successful handshake:
    ///
    /// | time | Initiator   | direction | Responder   |
    /// | ---  | ---:        | :---:     | :---        |
    /// | t0   | `InitHello` | ->        |             |
    /// | t1   |             | <-        | `RespHello` |
    /// | t2   | `InitConf`  | ->        |             |
    /// | t3   |             | <-        | `EmptyData` |
    pub fn handle_msg(&mut self, rx_buf: &[u8], tx_buf: &mut [u8]) -> Result<HandleMsgResult> {
        let seal_broken = "Message seal broken!";
        // length of the response. We assume no response, so None for now
        let mut len = 0;
        let mut exchanged = false;

        ensure!(!rx_buf.is_empty(), "received empty message, ignoring it");

        let msg_type = rx_buf[0].try_into();

        log::debug!("Rx {:?}, processing", msg_type);

        let peer = match msg_type {
            Ok(MsgType::InitHello) => {
                let msg_in: Ref<&[u8], Envelope<InitHello>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                let mut msg_out = truncating_cast_into::<Envelope<RespHello>>(tx_buf)?;
                let peer = self.handle_init_hello(&msg_in.payload, &mut msg_out.payload)?;
                len = self.seal_and_commit_msg(peer, MsgType::RespHello, &mut msg_out)?;
                peer
            }
            Ok(MsgType::RespHello) => {
                let msg_in: Ref<&[u8], Envelope<RespHello>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                let mut msg_out = truncating_cast_into::<Envelope<InitConf>>(tx_buf)?;
                let peer = self.handle_resp_hello(&msg_in.payload, &mut msg_out.payload)?;
                len = self.seal_and_commit_msg(peer, MsgType::InitConf, &mut msg_out)?;
                peer.hs()
                    .store_msg_for_retransmission(self, &msg_out.as_bytes()[..len])?;
                exchanged = true;
                peer
            }
            Ok(MsgType::InitConf) => {
                let msg_in: Ref<&[u8], Envelope<InitConf>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                let mut msg_out = truncating_cast_into::<Envelope<EmptyData>>(tx_buf)?;
                let (peer, if_exchanged) =
                    self.handle_init_conf(&msg_in.payload, &mut msg_out.payload)?;
                len = self.seal_and_commit_msg(peer, MsgType::EmptyData, &mut msg_out)?;
                exchanged = if_exchanged;
                peer
            }
            Ok(MsgType::EmptyData) => {
                let msg_in: Ref<&[u8], Envelope<EmptyData>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                self.handle_resp_conf(&msg_in.payload)?
            }
            Ok(MsgType::DataMsg) => bail!("DataMsg handling not implemented!"),
            Ok(MsgType::CookieReply) => {
                let msg_in: Ref<&[u8], CookieReply> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;
                let peer = self.handle_cookie_reply(&msg_in)?;
                len = 0;
                peer
            }
            Err(_) => {
                bail!("CookieReply handling not implemented!")
            }
        };

        Ok(HandleMsgResult {
            exchanged_with: exchanged.then_some(peer),
            resp: if len == 0 { None } else { Some(len) },
        })
    }

    /// Serialize message to `tx_buf`, generating the `mac` in the process of
    /// doing so. If `cookie_secret` is also present, a `cookie` value is also generated
    /// and added to the message
    ///
    /// The message type is explicitly required here because it is very easy to
    /// forget setting that, which creates subtle but far ranging errors.
    pub fn seal_and_commit_msg<M: AsBytes + FromBytes>(
        &mut self,
        peer: PeerPtr,
        msg_type: MsgType,
        msg: &mut Ref<&mut [u8], Envelope<M>>,
    ) -> Result<usize> {
        msg.msg_type = msg_type as u8;
        msg.seal(peer, self)?;
        Ok(size_of::<Envelope<M>>())
    }
}

// EVENT POLLING /////////////////////////////////

#[derive(Debug, Copy, Clone)]
pub struct Wait(Timing);

impl Wait {
    fn immediate() -> Self {
        Wait(0.0)
    }

    fn hibernate() -> Self {
        Wait(UNENDING)
    }

    fn immediate_unless(cond: bool) -> Self {
        if cond {
            Self::hibernate()
        } else {
            Self::immediate()
        }
    }

    fn or_hibernate(t: Option<Timing>) -> Self {
        match t {
            Some(u) => Wait(u),
            None => Wait::hibernate(),
        }
    }

    fn or_immediate(t: Option<Timing>) -> Self {
        match t {
            Some(u) => Wait(u),
            None => Wait::immediate(),
        }
    }

    fn and<T: Into<Wait>>(&self, o: T) -> Self {
        let (a, b) = (self.0, o.into().0);
        Wait(if a > b { a } else { b })
    }
}

impl From<Timing> for Wait {
    fn from(t: Timing) -> Wait {
        Wait(t)
    }
}

impl From<Option<Timing>> for Wait {
    fn from(t: Option<Timing>) -> Wait {
        Wait::or_hibernate(t)
    }
}

/// Result of a poll operation, containing prescriptive action for the outer
/// event loop
#[derive(Debug, Copy, Clone)]
pub enum PollResult {
    Sleep(Timing),
    DeleteKey(PeerPtr),
    SendInitiation(PeerPtr),
    SendRetransmission(PeerPtr),
}

impl Default for PollResult {
    fn default() -> Self {
        Self::hibernate()
    }
}

impl PollResult {
    pub fn hibernate() -> Self {
        Self::Sleep(UNENDING) // Avoid excessive sleep times (might trigger bugs on some platforms)
    }

    pub fn peer(&self) -> Option<PeerPtr> {
        use PollResult::*;
        match *self {
            DeleteKey(p) | SendInitiation(p) | SendRetransmission(p) => Some(p),
            _ => None,
        }
    }

    pub fn fold(&self, otr: PollResult) -> PollResult {
        use PollResult::*;
        match (*self, otr) {
            (Sleep(a), Sleep(b)) => Sleep(f64::min(a, b)),
            (a, Sleep(_b)) if a.saturated() => a,
            (Sleep(_a), b) if b.saturated() => b,
            _ => panic!(
                "Do not fold two saturated poll results! It doesn't make sense; \
                we would have to discard one of the events. \
                As soon as some result that requires an action (i.e. something other than sleep \
                is reached you should just return and have the API consumer poll again."
            ),
        }
    }

    pub fn try_fold_with<F: FnOnce() -> Result<PollResult>>(&self, f: F) -> Result<PollResult> {
        if self.saturated() {
            Ok(*self)
        } else {
            Ok(self.fold(f()?))
        }
    }

    pub fn poll_child<P: Pollable>(&self, srv: &mut CryptoServer, p: &P) -> Result<PollResult> {
        self.try_fold_with(|| p.poll(srv))
    }

    pub fn poll_children<P, I>(&self, srv: &mut CryptoServer, iter: I) -> Result<PollResult>
    where
        P: Pollable,
        I: Iterator<Item = P>,
    {
        let mut acc = *self;
        for e in iter {
            if acc.saturated() {
                break;
            }
            acc = acc.fold(e.poll(srv)?);
        }
        Ok(acc)
    }

    /// Execute `f` if it is ready, as indicated by `wait`
    pub fn sched<W: Into<Wait>, F: FnOnce() -> PollResult>(&self, wait: W, f: F) -> PollResult {
        let wait = wait.into().0;
        if self.saturated() {
            *self
        } else if has_happened(wait, 0.0) {
            self.fold(f())
        } else {
            self.fold(Self::Sleep(wait))
        }
    }

    pub fn try_sched<W: Into<Wait>, F: FnOnce() -> Result<PollResult>>(
        &self,
        wait: W,
        f: F,
    ) -> Result<PollResult> {
        let wait = wait.into().0;
        if self.saturated() {
            Ok(*self)
        } else if has_happened(wait, 0.0) {
            Ok(self.fold(f()?))
        } else {
            Ok(self.fold(Self::Sleep(wait)))
        }
    }

    pub fn ok(&self) -> Result<PollResult> {
        Ok(*self)
    }

    pub fn saturated(&self) -> bool {
        use PollResult::*;
        !matches!(self, Sleep(_))
    }
}

pub fn begin_poll() -> PollResult {
    PollResult::default()
}

/// Takes a closure `f`, returns another closure which internally calls f and
/// then returns a default [PollResult]
pub fn void_poll<T, F: FnOnce() -> T>(f: F) -> impl FnOnce() -> PollResult {
    || {
        f();
        PollResult::default()
    }
}

pub trait Pollable {
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult>;
}

impl CryptoServer {
    /// Implements something like [Pollable::poll] for the server, with a
    /// notable difference: since `self` already is the server, the signature
    /// has to be different; `self` must be a `&mut` and already is a borrow to
    /// the server, eluding the need for a second arg.
    pub fn poll(&mut self) -> Result<PollResult> {
        let r = begin_poll() // Poll each biscuit and peer until an event is found
            .poll_children(self, self.biscuit_key_ptrs())?
            .poll_children(self, self.cookie_secret_ptrs())?
            .poll_children(self, self.peer_ptrs_off(self.peer_poll_off))?;
        self.peer_poll_off = match r.peer() {
            Some(p) => p.0 + 1, // Event found while polling peer p; will poll peer p+1 next
            None => 0, // No peer ev found. Resetting to 0 out of an irrational fear of non-zero numbers
        };
        r.ok()
    }
}

impl Pollable for BiscuitKeyPtr {
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult> {
        begin_poll()
            .sched(self.life_left(srv), void_poll(|| self.get_mut(srv).erase())) // Erase stale biscuits
            .ok()
    }
}

impl Pollable for ServerCookieSecretPtr {
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult> {
        begin_poll()
            .sched(self.life_left(srv), void_poll(|| self.get_mut(srv).erase())) // Erase stale cookie secrets
            .ok()
    }
}

impl Pollable for PeerPtr {
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult> {
        let (ses, hs) = (self.session(), self.hs());
        begin_poll()
            .sched(hs.life_left(srv), void_poll(|| hs.take(srv))) // Silently erase old handshakes
            .sched(ses.life_left(srv), || {
                // Erase old sessions
                ses.take(srv);
                PollResult::DeleteKey(*self)
            })
            // Initialize the handshake
            // IF if initiation hasn't been requested (consumer of the API is free to
            // ignore the request hence there is a need to do record keeping on that)
            // AND after the existing session becomes stale or if there is session at all
            // AND after the current handshake becomes stale or there is no handshake at all
            .sched(
                Wait::immediate_unless(self.get(srv).initiation_requested)
                    .and(Wait::or_immediate(ses.youth_left(srv)))
                    .and(Wait::or_immediate(hs.youth_left(srv))),
                || {
                    self.get_mut(srv).initiation_requested = true;
                    PollResult::SendInitiation(*self)
                },
            )
            .poll_child(srv, &hs) // Defer to the handshake for polling (retransmissions)
    }
}

impl Pollable for IniHsPtr {
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult> {
        begin_poll().try_sched(self.retransmission_in(srv), || {
            // Registering retransmission even if app does not retransmit.
            // This explicitly permits applications to ignore the event.
            self.register_retransmission(srv)?;
            Ok(PollResult::SendRetransmission(self.peer()))
        })
    }
}

// MESSAGE RETRANSMISSION ////////////////////////

impl CryptoServer {
    pub fn retransmit_handshake(&mut self, peer: PeerPtr, tx_buf: &mut [u8]) -> Result<usize> {
        peer.hs().apply_retransmission(self, tx_buf)
    }
}

impl IniHsPtr {
    pub fn store_msg_for_retransmission(&self, srv: &mut CryptoServer, msg: &[u8]) -> Result<()> {
        let ih = self
            .get_mut(srv)
            .as_mut()
            .with_context(|| format!("No current handshake for peer {:?}", self.peer()))?;
        cpy_min(msg, &mut *ih.tx_buf);
        ih.tx_count = 0;
        ih.tx_len = msg.len();
        self.register_retransmission(srv)?;
        Ok(())
    }

    pub fn apply_retransmission(&self, srv: &mut CryptoServer, tx_buf: &mut [u8]) -> Result<usize> {
        let ih_tx_len: usize;

        {
            let ih = self
                .get_mut(srv)
                .as_mut()
                .with_context(|| format!("No current handshake for peer {:?}", self.peer()))?;
            cpy_min(&ih.tx_buf[..ih.tx_len], tx_buf);
            ih_tx_len = ih.tx_len;
        }

        // Add cookie to retransmitted message
        let mut envelope = truncating_cast_into::<Envelope<InitHello>>(tx_buf)?;
        envelope.seal_cookie(self.peer(), srv)?;

        Ok(ih_tx_len)
    }

    pub fn register_retransmission(&self, srv: &mut CryptoServer) -> Result<()> {
        let tb = srv.timebase.clone();
        let ih = self
            .get_mut(srv)
            .as_mut()
            .with_context(|| format!("No current handshake for peer {:?}", self.peer()))?;
        // Base delay, exponential increase, ±50% jitter
        ih.tx_retry_at = tb.now()
            + RETRANSMIT_DELAY_BEGIN
                * RETRANSMIT_DELAY_GROWTH.powf(
                    (RETRANSMIT_DELAY_END / RETRANSMIT_DELAY_BEGIN)
                        .log(RETRANSMIT_DELAY_GROWTH)
                        .min(ih.tx_count as f64),
                )
                * RETRANSMIT_DELAY_JITTER
                * (rand::random::<f64>() + 1.0); // TODO: Replace with the rand crate
        ih.tx_count += 1;
        Ok(())
    }

    pub fn register_immediate_retransmission(&self, srv: &mut CryptoServer) -> Result<()> {
        let tb = srv.timebase.clone();
        let ih = self
            .get_mut(srv)
            .as_mut()
            .with_context(|| format!("No current handshake for peer {:?}", self.peer()))?;
        ih.tx_retry_at = tb.now();
        ih.tx_count += 1;
        Ok(())
    }

    pub fn retransmission_in(&self, srv: &mut CryptoServer) -> Option<Timing> {
        self.get(srv)
            .as_ref()
            .map(|hs| hs.tx_retry_at - srv.timebase.now())
    }
}

// CRYPTO/HANDSHAKE HANDLING /////////////////////

impl<M> Envelope<M>
where
    M: AsBytes + FromBytes,
{
    /// Calculate the message authentication code (`mac`) and also append cookie value
    pub fn seal(&mut self, peer: PeerPtr, srv: &CryptoServer) -> Result<()> {
        let mac = hash_domains::mac()?
            .mix(peer.get(srv).spkt.secret())?
            .mix(&self.as_bytes()[span_of!(Self, msg_type..mac)])?;
        self.mac.copy_from_slice(mac.into_value()[..16].as_ref());
        self.seal_cookie(peer, srv)?;
        Ok(())
    }

    /// Calculate and append the cookie value if `cookie_key` exists (`cookie`)
    pub fn seal_cookie(&mut self, peer: PeerPtr, srv: &CryptoServer) -> Result<()> {
        if let Some(cookie_key) = &peer.cv().get(srv) {
            let cookie = hash_domains::cookie()?
                .mix(cookie_key.value.secret())?
                .mix(&self.as_bytes()[span_of!(Self, msg_type..cookie)])?;
            self.cookie
                .copy_from_slice(cookie.into_value()[..16].as_ref());
        }
        Ok(())
    }
}

impl<M> Envelope<M>
where
    M: AsBytes + FromBytes,
{
    /// Check the message authentication code
    pub fn check_seal(&self, srv: &CryptoServer) -> Result<bool> {
        let expected = hash_domains::mac()?
            .mix(srv.spkm.secret())?
            .mix(&self.as_bytes()[span_of!(Self, msg_type..mac)])?;
        Ok(constant_time::memcmp(
            &self.mac,
            &expected.into_value()[..16],
        ))
    }
}

impl InitiatorHandshake {
    pub fn zero_with_timestamp(srv: &CryptoServer) -> Self {
        InitiatorHandshake {
            created_at: srv.timebase.now(),
            next: HandshakeStateMachine::RespHello,
            core: HandshakeState::zero(),
            eski: ESk::zero(),
            epki: EPk::zero(),
            tx_at: 0.0,
            tx_retry_at: 0.0,
            tx_count: 0,
            tx_len: 0,
            tx_buf: MsgBuf::zero(),
            cookie_value: CookieStore::new(),
        }
    }
}

impl HandshakeState {
    pub fn zero() -> Self {
        Self {
            sidi: SessionId::zero(),
            sidr: SessionId::zero(),
            ck: SecretHashDomain::zero().dup(),
        }
    }

    pub fn erase(&mut self) {
        self.ck = SecretHashDomain::zero().dup();
    }

    pub fn init(&mut self, spkr: &[u8]) -> Result<&mut Self> {
        self.ck = hash_domains::ckinit()?.turn_secret().mix(spkr)?.dup();
        Ok(self)
    }

    pub fn mix(&mut self, a: &[u8]) -> Result<&mut Self> {
        self.ck = self.ck.mix(&hash_domains::mix()?)?.mix(a)?.dup();
        Ok(self)
    }

    pub fn encrypt_and_mix(&mut self, ct: &mut [u8], pt: &[u8]) -> Result<&mut Self> {
        let k = self.ck.mix(&hash_domains::hs_enc()?)?.into_secret();
        aead::encrypt(ct, k.secret(), &[0u8; aead::NONCE_LEN], &[], pt)?;
        self.mix(ct)
    }

    pub fn decrypt_and_mix(&mut self, pt: &mut [u8], ct: &[u8]) -> Result<&mut Self> {
        let k = self.ck.mix(&hash_domains::hs_enc()?)?.into_secret();
        aead::decrypt(pt, k.secret(), &[0u8; aead::NONCE_LEN], &[], ct)?;
        self.mix(ct)
    }

    // I loathe "error: constant expression depends on a generic parameter"
    pub fn encaps_and_mix<T: Kem<Error = Infallible>, const SHK_LEN: usize>(
        &mut self,
        ct: &mut [u8],
        pk: &[u8],
    ) -> Result<&mut Self> {
        let mut shk = Secret::<SHK_LEN>::zero();
        T::encaps(shk.secret_mut(), ct, pk)?;
        self.mix(pk)?.mix(shk.secret())?.mix(ct)
    }

    pub fn decaps_and_mix<T: Kem<Error = Infallible>, const SHK_LEN: usize>(
        &mut self,
        sk: &[u8],
        pk: &[u8],
        ct: &[u8],
    ) -> Result<&mut Self> {
        let mut shk = Secret::<SHK_LEN>::zero();
        T::decaps(shk.secret_mut(), sk, ct)?;
        self.mix(pk)?.mix(shk.secret())?.mix(ct)
    }

    pub fn store_biscuit(
        &mut self,
        srv: &mut CryptoServer,
        peer: PeerPtr,
        biscuit_ct: &mut [u8],
    ) -> Result<&mut Self> {
        let mut biscuit = Secret::<BISCUIT_PT_LEN>::zero(); // pt buffer
        let mut biscuit: Ref<&mut [u8], Biscuit> =
            Ref::new(biscuit.secret_mut().as_mut_slice()).unwrap();

        // calculate pt contents
        biscuit
            .pidi
            .copy_from_slice(peer.get(srv).pidt()?.as_slice());
        biscuit.biscuit_no.copy_from_slice(&*srv.biscuit_ctr);
        biscuit
            .ck
            .copy_from_slice(self.ck.clone().danger_into_secret().secret());

        // calculate ad contents
        let ad = hash_domains::biscuit_ad()?
            .mix(srv.spkm.secret())?
            .mix(self.sidi.as_slice())?
            .mix(self.sidr.as_slice())?
            .into_value();

        // consume biscuit no
        constant_time::increment(&mut *srv.biscuit_ctr);

        // The first bit of the nonce indicates which biscuit key was used
        // TODO: This is premature optimization. Remove!
        let bk = srv.active_biscuit_key();
        let mut n = XAEADNonce::random();
        n[0] &= 0b0111_1111;
        n[0] |= (bk.0 as u8 & 0x1) << 7;

        let k = bk.get(srv).value.secret();
        let pt = biscuit.as_bytes();
        xaead::encrypt(biscuit_ct, k, &*n, &ad, pt)?;

        self.mix(biscuit_ct)
    }

    /// Takes an encrypted biscuit and tries to decrypt the contained
    /// information
    pub fn load_biscuit(
        srv: &CryptoServer,
        biscuit_ct: &[u8],
        sidi: SessionId,
        sidr: SessionId,
    ) -> Result<(PeerPtr, BiscuitId, HandshakeState)> {
        // The first bit of the biscuit indicates which biscuit key was used
        let bk = BiscuitKeyPtr(((biscuit_ct[0] & 0b1000_0000) >> 7) as usize);

        // Calculate additional data fields
        let ad = hash_domains::biscuit_ad()?
            .mix(srv.spkm.secret())?
            .mix(sidi.as_slice())?
            .mix(sidr.as_slice())?
            .into_value();

        // Allocate and decrypt the biscuit data
        let mut biscuit = Secret::<BISCUIT_PT_LEN>::zero(); // pt buf
        let mut biscuit: Ref<&mut [u8], Biscuit> =
            Ref::new(biscuit.secret_mut().as_mut_slice()).unwrap();
        xaead::decrypt(
            biscuit.as_bytes_mut(),
            bk.get(srv).value.secret(),
            &ad,
            biscuit_ct,
        )?;

        // Reconstruct the biscuit fields
        let no = BiscuitId::from_slice(&biscuit.biscuit_no);
        let ck = SecretHashDomain::danger_from_secret(Secret::from_slice(&biscuit.ck)).dup();
        let pid = PeerId::from_slice(&biscuit.pidi);

        // Reconstruct the handshake state
        let mut hs = Self { sidi, sidr, ck };
        hs.mix(biscuit_ct)?;

        // Look up the associated peer
        let peer = srv
            .find_peer(pid) // TODO: FindPeer should return a Result<()>
            .with_context(|| format!("Could not decode biscuit for peer {pid:?}: No such peer."))?;

        // Defense against replay attacks; implementations may accept
        // the most recent biscuit no again (bn = peer.bn_{prev}) which
        // indicates retransmission
        // TODO: Handle retransmissions without involving the crypto code
        ensure!(
            constant_time::compare(&biscuit.biscuit_no, &*peer.get(srv).biscuit_used) >= 0,
            "Rejecting biscuit: Outdated biscuit number"
        );

        Ok((peer, no, hs))
    }

    pub fn enter_live(self, srv: &CryptoServer, role: HandshakeRole) -> Result<Session> {
        let HandshakeState { ck, sidi, sidr } = self;
        let tki = ck.mix(&hash_domains::ini_enc()?)?.into_secret();
        let tkr = ck.mix(&hash_domains::res_enc()?)?.into_secret();
        let created_at = srv.timebase.now();
        let (ntx, nrx) = (0, 0);
        let (mysid, peersid, ktx, krx) = match role {
            HandshakeRole::Initiator => (sidi, sidr, tki, tkr),
            HandshakeRole::Responder => (sidr, sidi, tkr, tki),
        };
        Ok(Session {
            created_at,
            sidm: mysid,
            sidt: peersid,
            handshake_role: role,
            ck,
            txkm: ktx,
            txkt: krx,
            txnm: ntx,
            txnt: nrx,
        })
    }
}

impl CryptoServer {
    /// Get the shared key that was established with given peer
    ///
    /// Fail if no session is available with the peer
    pub fn osk(&self, peer: PeerPtr) -> Result<SymKey> {
        let session = peer
            .session()
            .get(self)
            .as_ref()
            .with_context(|| format!("No current session for peer {:?}", peer))?;
        Ok(session.ck.mix(&hash_domains::osk()?)?.into_secret())
    }
}

impl CryptoServer {
    /// Implementation of the cryptographic protocol using the already
    /// established primitives
    pub fn handle_initiation(&mut self, peer: PeerPtr, ih: &mut InitHello) -> Result<PeerPtr> {
        let mut hs = InitiatorHandshake::zero_with_timestamp(self);

        // IHI1
        hs.core.init(peer.get(self).spkt.secret())?;

        // IHI2
        hs.core.sidi.randomize();
        ih.sidi.copy_from_slice(&hs.core.sidi.value);

        // IHI3
        EphemeralKem::keygen(hs.eski.secret_mut(), &mut *hs.epki)?;
        ih.epki.copy_from_slice(&hs.epki.value);

        // IHI4
        hs.core.mix(ih.sidi.as_slice())?.mix(ih.epki.as_slice())?;

        // IHI5
        hs.core
            .encaps_and_mix::<StaticKem, { StaticKem::SHK_LEN }>(
                ih.sctr.as_mut_slice(),
                peer.get(self).spkt.secret(),
            )?;

        // IHI6
        hs.core
            .encrypt_and_mix(ih.pidic.as_mut_slice(), self.pidm()?.as_ref())?;

        // IHI7
        hs.core
            .mix(self.spkm.secret())?
            .mix(peer.get(self).psk.secret())?;

        // IHI8
        hs.core.encrypt_and_mix(ih.auth.as_mut_slice(), &[])?;

        // Update the handshake hash last (not changing any state on prior error
        peer.hs().insert(self, hs)?;

        Ok(peer)
    }

    pub fn handle_init_hello(&mut self, ih: &InitHello, rh: &mut RespHello) -> Result<PeerPtr> {
        let mut core = HandshakeState::zero();

        core.sidi = SessionId::from_slice(&ih.sidi);

        // IHR1
        core.init(self.spkm.secret())?;

        // IHR4
        core.mix(&ih.sidi)?.mix(&ih.epki)?;

        // IHR5
        core.decaps_and_mix::<StaticKem, { StaticKem::SHK_LEN }>(
            self.sskm.secret(),
            self.spkm.secret(),
            &ih.sctr,
        )?;

        // IHR6
        let peer = {
            let mut peerid = PeerId::zero();
            core.decrypt_and_mix(&mut *peerid, &ih.pidic)?;
            self.find_peer(peerid)
                .with_context(|| format!("No such peer {peerid:?}."))?
        };

        // IHR7
        core.mix(peer.get(self).spkt.secret())?
            .mix(peer.get(self).psk.secret())?;

        // IHR8
        core.decrypt_and_mix(&mut [0u8; 0], &ih.auth)?;

        // RHR1
        core.sidr.randomize();
        rh.sidi.copy_from_slice(core.sidi.as_ref());
        rh.sidr.copy_from_slice(core.sidr.as_ref());

        // RHR3
        core.mix(&rh.sidr)?.mix(&rh.sidi)?;

        // RHR4
        core.encaps_and_mix::<EphemeralKem, { EphemeralKem::SHK_LEN }>(&mut rh.ecti, &ih.epki)?;

        // RHR5
        core.encaps_and_mix::<StaticKem, { StaticKem::SHK_LEN }>(
            &mut rh.scti,
            peer.get(self).spkt.secret(),
        )?;

        // RHR6
        core.store_biscuit(self, peer, &mut rh.biscuit)?;

        // RHR7
        core.encrypt_and_mix(&mut rh.auth, &[])?;

        Ok(peer)
    }

    pub fn handle_resp_hello(&mut self, rh: &RespHello, ic: &mut InitConf) -> Result<PeerPtr> {
        // RHI2
        let peer = self
            .lookup_handshake(SessionId::from_slice(&rh.sidi))
            .with_context(|| {
                format!(
                    "Got RespHello packet for non-existent session {:?}",
                    rh.sidi
                )
            })?
            .peer();

        macro_rules! hs {
            () => {
                peer.hs().get(self).as_ref().unwrap()
            };
        }
        macro_rules! hs_mut {
            () => {
                peer.hs().get_mut(self).as_mut().unwrap()
            };
        }

        // TODO: Is this really necessary? The only possible state is "awaits resp hello";
        // no initiation created should be modeled as an Null option and a Session means
        // we will not be able to find the handshake
        let exp = hs!().next;
        let got = HandshakeStateMachine::RespHello;

        ensure!(
            exp == got,
            "Unexpected package in session {:?}. Expected {:?}, got {:?}.",
            SessionId::from_slice(&rh.sidi),
            exp,
            got
        );

        let mut core = hs!().core.clone();
        core.sidr.copy_from_slice(&rh.sidr);

        // TODO: decaps_and_mix should take Secret<> directly
        //       to save us from the repetitive secret unwrapping

        // RHI3
        core.mix(&rh.sidr)?.mix(&rh.sidi)?;

        // RHI4
        core.decaps_and_mix::<EphemeralKem, { EphemeralKem::SHK_LEN }>(
            hs!().eski.secret(),
            &*hs!().epki,
            &rh.ecti,
        )?;

        // RHI5
        core.decaps_and_mix::<StaticKem, { StaticKem::SHK_LEN }>(
            self.sskm.secret(),
            self.spkm.secret(),
            &rh.scti,
        )?;

        // RHI6
        core.mix(&rh.biscuit)?;

        // RHI7
        core.decrypt_and_mix(&mut [0u8; 0], &rh.auth)?;

        // TODO: We should just authenticate the entire network package up to the auth
        // tag as a pattern instead of mixing in fields separately

        ic.sidi.copy_from_slice(&rh.sidi);
        ic.sidr.copy_from_slice(&rh.sidr);

        // ICI3
        core.mix(&ic.sidi)?.mix(&ic.sidr)?;
        ic.biscuit.copy_from_slice(&rh.biscuit);

        // ICI4
        core.encrypt_and_mix(&mut ic.auth, &[])?;

        // Split() – We move the secrets into the session; we do not
        // delete the InitiatorHandshake, just clear it's secrets because
        // we still need it for InitConf message retransmission to function.

        // ICI7
        peer.session()
            .insert(self, core.enter_live(self, HandshakeRole::Initiator)?)?;
        hs_mut!().core.erase();
        hs_mut!().next = HandshakeStateMachine::RespConf;

        Ok(peer)
    }

    pub fn handle_init_conf(
        &mut self,
        ic: &InitConf,
        rc: &mut EmptyData,
    ) -> Result<(PeerPtr, bool)> {
        let mut exchanged = false;
        // (peer, bn) ← LoadBiscuit(InitConf.biscuit)
        // ICR1
        let (peer, biscuit_no, mut core) = HandshakeState::load_biscuit(
            self,
            &ic.biscuit,
            SessionId::from_slice(&ic.sidi),
            SessionId::from_slice(&ic.sidr),
        )?;

        // ICR2
        core.encrypt_and_mix(&mut [0u8; aead::TAG_LEN], &[])?;

        // ICR3
        core.mix(&ic.sidi)?.mix(&ic.sidr)?;

        // ICR4
        core.decrypt_and_mix(&mut [0u8; 0], &ic.auth)?;

        // ICR5
        if constant_time::compare(&*biscuit_no, &*peer.get(self).biscuit_used) > 0 {
            // ICR6
            peer.get_mut(self).biscuit_used = biscuit_no;

            // ICR7
            peer.session()
                .insert(self, core.enter_live(self, HandshakeRole::Responder)?)?;
            // TODO: This should be part of the protocol specification.
            // Abort any ongoing handshake from initiator role
            peer.hs().take(self);

            // Only exchange key on new biscuit number- avoid duplicate key exchanges on retransmitted InitConf messages
            exchanged = true;
        }

        // TODO: Implementing RP should be possible without touching the live session stuff
        // TODO: I fear that this may lead to race conditions; the acknowledgement may be
        //       sent on a different session than the incoming packet. This should be mitigated
        //       by the deliberate back off in SessionPtr::retire_at as in practice only one
        //       handshake should be going on at a time.
        //       I think it may not be possible to formulate the protocol in such a way that
        //       we can be sure that the other party possesses a matching key; maybe we should
        //       study mathematically whether this even is possible.
        //       WireGuard solves this by just having multiple sessions so even if there is a
        //       race condition leading to two concurrent active sessions, data can still be sent.
        //       It would be nice if Rosenpass could do the same, but in order for that to work,
        //       WireGuard would have to have support for multiple PSKs (with a timeout) and
        //       WireGuard; to identify which PSK was used, wireguard would have to do a linear
        //       search with the responder trying each available PSK.
        //       In practice, the best thing to do might be to send regular pings to confirm that
        //       the key is still the same, which adds a bit of overhead.
        //       Another option would be to monitor WireGuard for failing handshakes and trigger
        //       a Rosenpass handshake in case a key mismatch due to a race condition is the reason
        //       for the failing handshake.

        // Send ack – Implementing sending the empty acknowledgement here
        // instead of a generic PeerPtr::send(&Server, Option<&[u8]>) -> Either<EmptyData, Data>
        // because data transmission is a stub currently. This software is supposed to be used
        // as a key exchange service feeding a PSK into some classical (i.e. non post quantum)
        let ses = peer
            .session()
            .get_mut(self)
            .as_mut()
            .context("Cannot send acknowledgement. No session.")?;
        rc.sid.copy_from_slice(&ses.sidt.value);
        rc.ctr.copy_from_slice(&ses.txnm.to_le_bytes());
        ses.txnm += 1; // Increment nonce before encryption, just in case an error is raised

        let n = cat!(aead::NONCE_LEN; &rc.ctr, &[0u8; 4]);
        let k = ses.txkm.secret();
        aead::encrypt(&mut rc.auth, k, &n, &[], &[])?; // ct, k, n, ad, pt

        Ok((peer, exchanged))
    }

    pub fn handle_resp_conf(&mut self, rc: &EmptyData) -> Result<PeerPtr> {
        let sid = SessionId::from_slice(&rc.sid);
        let hs = self
            .lookup_handshake(sid)
            .with_context(|| format!("Got RespConf packet for non-existent session {sid:?}"))?;
        let ses = hs.peer().session();

        let exp = hs.get(self).as_ref().map(|h| h.next);
        let got = Some(HandshakeStateMachine::RespConf);
        ensure!(
            exp == got,
            "Unexpected package in session {:?}. Expected {:?}, got {:?}.",
            sid,
            exp,
            got
        );

        // Validate the message
        {
            let s = ses.get_mut(self).as_mut().with_context(|| {
                format!("Cannot validate EmptyData message. Missing encryption session for {sid:?}")
            })?;
            // the unwrap can not fail, because the slice returned by ctr() is
            // guaranteed to have the correct size
            let n = u64::from_le_bytes(rc.ctr);
            ensure!(n >= s.txnt, "Stale nonce");
            s.txnt = n;
            aead::decrypt(
                // pt, k, n, ad, ct
                &mut [0u8; 0],
                s.txkt.secret(),
                &cat!(aead::NONCE_LEN; &rc.ctr, &[0u8; 4]),
                &[],
                &rc.auth,
            )?;
        }

        // We can now stop retransmitting RespConf
        hs.take(self);

        Ok(hs.peer())
    }

    pub fn handle_cookie_reply(&mut self, cr: &CookieReply) -> Result<PeerPtr> {
        let peer_ptr: Option<PeerPtr> = self
            .lookup_session(Public::new(cr.inner.sid))
            .map(|v| PeerPtr(v.0))
            .or_else(|| {
                self.lookup_handshake(Public::new(cr.inner.sid))
                    .map(|v| PeerPtr(v.0))
            });
        if let Some(peer) = peer_ptr {
            // Get last transmitted handshake message
            if let Some(ih) = &peer.get(self).handshake {
                let mut mac = [0u8; MAC_SIZE];
                // TODO: Handle buffer overflow in ih.tx_buf[0] (i.e. the case where the )
                match ih.tx_buf[0].try_into() {
                    Ok(MsgType::InitHello) => {
                        match truncating_cast_into_nomut::<Envelope<InitHello>>(&ih.tx_buf.value) {
                            Ok(t) => {
                                mac = t.mac;
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    }
                    Ok(MsgType::InitConf) => {
                        match truncating_cast_into_nomut::<Envelope<InitConf>>(&ih.tx_buf.value) {
                            Ok(t) => {
                                mac = t.mac;
                                Ok(())
                            }
                            Err(e) => Err(e),
                        }
                    }
                    _ => bail!(
                        "No last sent message for peer {pidr:?} to decrypt cookie reply.",
                        pidr = cr.inner.sid
                    ),
                }?;

                let spkt = peer.get(self).spkt.secret();
                let cookie_key = hash_domains::cookie_key()?.mix(spkt)?.into_value();
                let cookie_value = peer.cv().update_mut(self).unwrap();

                xaead::decrypt(cookie_value, &cookie_key, &mac, &cr.inner.cookie_encrypted)?;

                // Immediately retransmit on recieving a cookie reply message
                peer.hs().register_immediate_retransmission(self)?;

                Ok(peer)
            } else {
                bail!(
                    "No last sent message for peer {pidr:?} to decrypt cookie reply.",
                    pidr = cr.inner.sid
                );
            }
        } else {
            bail!("No such peer {pidr:?}.", pidr = cr.inner.sid);
        }
    }
}

fn truncating_cast_into<T: FromBytes>(buf: &mut [u8]) -> Result<Ref<&mut [u8], T>, RosenpassError> {
    Ref::new(&mut buf[..size_of::<T>()]).ok_or(RosenpassError::BufferSizeMismatch)
}

// TODO: This is bad…
fn truncating_cast_into_nomut<T: FromBytes>(buf: &[u8]) -> Result<Ref<&[u8], T>, RosenpassError> {
    Ref::new(&buf[..size_of::<T>()]).ok_or(RosenpassError::BufferSizeMismatch)
}

#[cfg(test)]
mod test {
    use std::{net::SocketAddrV4, thread::sleep, time::Duration};

    use super::*;

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

    #[test]
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
    fn handles_incorrect_size_messages() {
        stacker::grow(8 * 1024 * 1024, || {
            const OVERSIZED_MESSAGE: usize = ((MAX_MESSAGE_LEN as f32) * 1.2) as usize;
            type MsgBufPlus = Public<OVERSIZED_MESSAGE>;

            const PEER0: PeerPtr = PeerPtr(0);

            let (mut me, mut they) = make_server_pair().unwrap();
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
        StaticKem::keygen(sk.secret_mut(), pk.secret_mut())?;
        Ok((sk, pk))
    }

    fn make_server_pair() -> Result<(CryptoServer, CryptoServer)> {
        // TODO: Copied from the benchmark; deduplicate
        let psk = SymKey::random();
        let ((ska, pka), (skb, pkb)) = (keygen()?, keygen()?);
        let (mut a, mut b) = (
            CryptoServer::new(ska, pka.clone()),
            CryptoServer::new(skb, pkb.clone()),
        );
        a.add_peer(Some(psk.clone()), pkb)?;
        b.add_peer(Some(psk), pka)?;
        Ok((a, b))
    }

    #[test]
    fn test_regular_exchange() {
        stacker::grow(8 * 1024 * 1024, || {
            type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
            let (mut a, mut b) = make_server_pair().unwrap();

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
                resp,
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
    fn test_regular_init_conf_retransmit() {
        stacker::grow(8 * 1024 * 1024, || {
            type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
            let (mut a, mut b) = make_server_pair().unwrap();

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
                resp,
                exchanged_with,
            } = b
                .handle_msg(&a_to_b_buf.as_slice()[..init_conf_len], &mut *b_to_a_buf)
                .unwrap();

            let empty_data_msg_type: MsgType = b_to_a_buf.value[0].try_into().unwrap();

            assert_eq!(exchanged_with, Some(PeerPtr(0)));
            assert_eq!(empty_data_msg_type, MsgType::EmptyData);

            //B handles InitConf again, sends EmptyData
            let HandleMsgResult {
                resp,
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
    fn cookie_reply_mechanism_responder_under_load() {
        stacker::grow(8 * 1024 * 1024, || {
            type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
            let (mut a, mut b) = make_server_pair().unwrap();

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

            let expected_cookie_value = hash_domains::cookie_value()
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
                        break (a.retransmit_handshake(peer, &mut *a_to_b_buf).unwrap());
                    }
                    PollResult::Sleep(time) => {
                        sleep(Duration::from_secs_f64(time));
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
    fn cookie_reply_mechanism_initiator_bails_on_message_under_load() {
        stacker::grow(8 * 1024 * 1024, || {
            type MsgBufPlus = Public<MAX_MESSAGE_LEN>;
            let (mut a, mut b) = make_server_pair().unwrap();

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
}
