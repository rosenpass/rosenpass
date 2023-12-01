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
//! use rosenpass::{
//!     pqkem::{StaticKEM, KEM},
//!     protocol::{SSk, SPk, MsgBuf, PeerPtr, CryptoServer, SymKey},
//! };
//! # fn main() -> anyhow::Result<()> {
//!
//! // always initialize libsodium before anything
//! rosenpass_sodium::init()?;
//!
//! // initialize secret and public key for peer a ...
//! let (mut peer_a_sk, mut peer_a_pk) = (SSk::zero(), SPk::zero());
//! StaticKEM::keygen(peer_a_sk.secret_mut(), peer_a_pk.secret_mut())?;
//!
//! // ... and for peer b
//! let (mut peer_b_sk, mut peer_b_pk) = (SSk::zero(), SPk::zero());
//! StaticKEM::keygen(peer_b_sk.secret_mut(), peer_b_pk.secret_mut())?;
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

use crate::{
    coloring::*,
    labeled_prf as lprf,
    msgs::*,
    pqkem::*,
    prftree::{SecretPrfTree, SecretPrfTreeBranch},
};
use rosenpass_ciphers::{aead, xaead, KEY_LEN};
use rosenpass_util::{cat, mem::cpy_min, ord::max_usize, time::Timebase};
use std::collections::hash_map::{
    Entry::{Occupied, Vacant},
    HashMap,
};

use log::{error};
use thiserror::Error;


#[derive(Error, Debug)]
enum CryptoServerError {
    #[error("An error occurred: {0}")]
    CustomError(String),
    // Add more error variants as needed
}

type CryptoServerResult<T> = Result<T, CryptoServerError>;


// CONSTANTS & SETTINGS //////////////////////////

/// Size required to fit any message in binary form
pub const RTX_BUFFER_SIZE: usize = max_usize(
    <Envelope<(), InitHello<()>> as LenseView>::LEN,
    <Envelope<(), InitConf<()>> as LenseView>::LEN,
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

pub type SPk = Secret<{ StaticKEM::PK_LEN }>; // Just Secret<> instead of Public<> so it gets allocated on the heap
pub type SSk = Secret<{ StaticKEM::SK_LEN }>;
pub type EPk = Public<{ EphemeralKEM::PK_LEN }>;
pub type ESk = Secret<{ EphemeralKEM::SK_LEN }>;

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
}

/// A Biscuit is like a fancy cookie. To avoid state disruption attacks,
/// the responder doesn't store state. Instead the state is stored in a
/// Biscuit, that is encrypted using the [BiscuitKey] which is only known to
/// the Responder. Thus secrecy of the Responder state is not violated, still
/// the responder can avoid storing this state.
#[derive(Debug)]
pub struct BiscuitKey {
    pub created_at: Timing,
    pub key: SymKey,
}

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
    pub ck: SecretPrfTreeBranch,
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
}

#[derive(Debug)]
pub struct Session {
    // Metadata
    pub created_at: Timing,
    pub sidm: SessionId,
    pub sidt: SessionId,
    pub handshake_role: HandshakeRole,
    // Crypto
    pub ck: SecretPrfTreeBranch,
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
    ) -> CryptoServerResult<&'a mut InitiatorHandshake> {
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

    pub fn insert<'a>(&self, srv: &'a mut CryptoServer, ses: Session) -> CryptoServerResult<&'a mut Session> {
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
            biscuit_keys: [BiscuitKey::new(), BiscuitKey::new()],
            peers: Vec::new(),
            index: HashMap::new(),
            peer_poll_off: 0,
        }
    }

    /// Iterate over the many (2) biscuit keys
    pub fn biscuit_key_ptrs(&self) -> impl Iterator<Item = BiscuitKeyPtr> {
        (0..self.biscuit_keys.len()).map(BiscuitKeyPtr)
    }

    #[rustfmt::skip]
    pub fn pidm(&self) -> CryptoServerResult<PeerId> {
        Ok(Public::new(
            lprf::peerid()?
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
    pub fn add_peer(&mut self, psk: Option<SymKey>, pk: SPk) -> CryptoServerResult<PeerPtr> {
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
            Occupied(_) => 
            return Err(CryptoServerError::CustomError(format!(
                "Cannot insert peer with id {:?}; peer with this id already registered.",
                peerid
            )));
            Vacant(e) => e.insert(peerno),
        };
        self.peers.push(peer);
        Ok(PeerPtr(peerno))
    }

    /// Register a new session (during a successful handshake, persisting longer
    /// than the handshake). Might return an error on session id collision
    pub fn register_session(&mut self, id: SessionId, peer: PeerPtr) -> CryptoServerResult<()> {
        match self.index.entry(IndexKey::Sid(id)) {
            Occupied(p) if PeerPtr(*p.get()) == peer => {} // Already registered
            Occupied(_) => 
            return Err(CryptoServerError::CustomError(format!(
                "Cannot insert session with id {:?}; id is in use.", id
            ))),
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
    pub fn pidt(&self) -> CryptoServerResult<PeerId> {
        Ok(Public::new(
            lprf::peerid()?
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
            ck: SecretPrfTree::zero().dup(),
            txkm: SymKey::zero(),
            txkt: SymKey::zero(),
            txnm: 0,
            txnt: 0,
        }
    }
}

// BISCUIT KEY ///////////////////////////////////

/// Biscuit Keys are always randomized, so that even if through a bug some
/// secrete is encrypted with an initialized [BiscuitKey], nobody instead of
/// everybody may read the secret.
impl BiscuitKey {
    // new creates a random value, that might be counterintuitive for a Default
    // impl
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            created_at: BCE,
            key: SymKey::random(),
        }
    }

    pub fn erase(&mut self) {
        self.key.randomize();
        self.created_at = BCE;
    }

    pub fn randomize(&mut self, tb: &Timebase) {
        self.key.randomize();
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
    pub fn initiate_handshake(&mut self, peer: PeerPtr, tx_buf: &mut [u8]) -> CryptoServerResult<usize> {
        let mut msg = tx_buf.envelope_truncating::<InitHello<()>>()?; // Envelope::<InitHello>::default(); // TODO
        self.handle_initiation(peer, msg.payload_mut().init_hello()?)?;
        let len = self.seal_and_commit_msg(peer, MsgType::InitHello, msg)?;
        peer.hs()
            .store_msg_for_retransmission(self, &tx_buf[..len])?;
        Ok(len)
    }
}

#[derive(Debug)]
pub struct HandleMsgResult {
    pub exchanged_with: Option<PeerPtr>,
    pub resp: Option<usize>,
}

impl CryptoServer {
    /// Respond to an incoming message
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
    pub fn handle_msg(&mut self, rx_buf: &[u8], tx_buf: &mut [u8]) -> CryptoServerResult<HandleMsgResult> {
        let seal_broken = "Message seal broken!";
        // length of the response. We assume no response, so None for now
        let mut len = 0;
        let mut exchanged = false;

        ensure!(!rx_buf.is_empty(), "received empty message, ignoring it");

        let peer = match rx_buf[0].try_into() {
            Ok(MsgType::InitHello) => {
                let msg_in = rx_buf.envelope::<InitHello<&[u8]>>()?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                let mut msg_out = tx_buf.envelope_truncating::<RespHello<&mut [u8]>>()?;
                let peer = self.handle_init_hello(
                    msg_in.payload().init_hello()?,
                    msg_out.payload_mut().resp_hello()?,
                )?;
                len = self.seal_and_commit_msg(peer, MsgType::RespHello, msg_out)?;
                peer
            }
            Ok(MsgType::RespHello) => {
                let msg_in = rx_buf.envelope::<RespHello<&[u8]>>()?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                let mut msg_out = tx_buf.envelope_truncating::<InitConf<&mut [u8]>>()?;
                let peer = self.handle_resp_hello(
                    msg_in.payload().resp_hello()?,
                    msg_out.payload_mut().init_conf()?,
                )?;
                len = self.seal_and_commit_msg(peer, MsgType::InitConf, msg_out)?;
                peer.hs()
                    .store_msg_for_retransmission(self, &tx_buf[..len])?;
                exchanged = true;
                peer
            }
            Ok(MsgType::InitConf) => {
                let msg_in = rx_buf.envelope::<InitConf<&[u8]>>()?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                let mut msg_out = tx_buf.envelope_truncating::<EmptyData<&mut [u8]>>()?;
                let peer = self.handle_init_conf(
                    msg_in.payload().init_conf()?,
                    msg_out.payload_mut().empty_data()?,
                )?;
                len = self.seal_and_commit_msg(peer, MsgType::EmptyData, msg_out)?;
                exchanged = true;
                peer
            }
            Ok(MsgType::EmptyData) => {
                let msg_in = rx_buf.envelope::<EmptyData<&[u8]>>()?;
                ensure!(msg_in.check_seal(self)?, seal_broken);

                self.handle_resp_conf(msg_in.payload().empty_data()?)?
            }
            Ok(MsgType::DataMsg) =>
            return Err(CryptoServerError::CustomError(format!(
                "DataMsg handling not implemented!"
            ))),
            Ok(MsgType::CookieReply) => bail!("CookieReply handling not implemented!"),
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
    /// doing so
    ///
    /// The message type is explicitly required here because it is very easy to
    /// forget setting that, which creates subtle but far ranging errors.
    pub fn seal_and_commit_msg<M: LenseView>(
        &mut self,
        peer: PeerPtr,
        msg_type: MsgType,
        mut msg: Envelope<&mut [u8], M>,
    ) -> CryptoServerResult<usize> {
        msg.msg_type_mut()[0] = msg_type as u8;
        msg.seal(peer, self)?;
        Ok(<Envelope<(), M> as LenseView>::LEN)
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

    pub fn try_fold_with<F: FnOnce() -> CryptoServerResult<PollResult>>(&self, f: F) -> CryptoServerResult<PollResult> {
        if self.saturated() {
            Ok(*self)
        } else {
            Ok(self.fold(f()?))
        }
    }

    pub fn poll_child<P: Pollable>(&self, srv: &mut CryptoServer, p: &P) -> CryptoServerResult<PollResult> {
        self.try_fold_with(|| p.poll(srv))
    }

    pub fn poll_children<P, I>(&self, srv: &mut CryptoServer, iter: I) -> CryptoServerResult<PollResult>
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

    pub fn try_sched<W: Into<Wait>, F: FnOnce() -> CryptoServerResult<PollResult>>(
        &self,
        wait: W,
        f: F,
    ) -> CryptoServerResult<PollResult> {
        let wait = wait.into().0;
        if self.saturated() {
            Ok(*self)
        } else if has_happened(wait, 0.0) {
            Ok(self.fold(f()?))
        } else {
            Ok(self.fold(Self::Sleep(wait)))
        }
    }

    pub fn ok(&self) -> CryptoServerResult<PollResult> {
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
    fn poll(&self, srv: &mut CryptoServer) -> CryptoServerResult<PollResult>;
}

impl CryptoServer {
    /// Implements something like [Pollable::poll] for the server, with a
    /// notable difference: since `self` already is the server, the signature
    /// has to be different; `self` must be a `&mut` and already is a borrow to
    /// the server, eluding the need for a second arg.
    pub fn poll(&mut self) -> CryptoServerResult<PollResult> {
        let r = begin_poll() // Poll each biscuit and peer until an event is found
            .poll_children(self, self.biscuit_key_ptrs())?
            .poll_children(self, self.peer_ptrs_off(self.peer_poll_off))?;
        self.peer_poll_off = match r.peer() {
            Some(p) => p.0 + 1, // Event found while polling peer p; will poll peer p+1 next
            None => 0, // No peer ev found. Resetting to 0 out of an irrational fear of non-zero numbers
        };
        r.ok()
    }
}

impl Pollable for BiscuitKeyPtr {
    fn poll(&self, srv: &mut CryptoServer) -> CryptoServerResult<PollResult> {
        begin_poll()
            .sched(self.life_left(srv), void_poll(|| self.get_mut(srv).erase())) // Erase stale biscuits
            .ok()
    }
}

impl Pollable for PeerPtr {
    fn poll(&self, srv: &mut CryptoServer) -> CryptoServerResult<PollResult> {
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
    fn poll(&self, srv: &mut CryptoServer) -> CryptoServerResult<PollResult> {
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
    pub fn retransmit_handshake(&mut self, peer: PeerPtr, tx_buf: &mut [u8]) -> CryptoServerResult<usize> {
        peer.hs().apply_retransmission(self, tx_buf)
    }
}

impl IniHsPtr {
    pub fn store_msg_for_retransmission(&self, srv: &mut CryptoServer, msg: &[u8]) -> CryptoServerResult<()> {
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

    pub fn apply_retransmission(&self, srv: &mut CryptoServer, tx_buf: &mut [u8]) -> CryptoServerResult<usize> {
        let ih = self
            .get_mut(srv)
            .as_mut()
            .with_context(|| format!("No current handshake for peer {:?}", self.peer()))?;
        cpy_min(&ih.tx_buf[..ih.tx_len], tx_buf);
        Ok(ih.tx_len)
    }

    pub fn register_retransmission(&self, srv: &mut CryptoServer) -> CryptoServerResult<()> {
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
                * (rosenpass_sodium::helpers::rand_f64() + 1.0); // TODO: Replace with the rand crate
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

impl<M> Envelope<&mut [u8], M>
where
    M: LenseView,
{
    /// Calculate the message authentication code (`mac`)
    pub fn seal(&mut self, peer: PeerPtr, srv: &CryptoServer) -> CryptoServerResult<()> {
        let mac = lprf::mac()?
            .mix(peer.get(srv).spkt.secret())?
            .mix(self.until_mac())?;
        self.mac_mut()
            .copy_from_slice(mac.into_value()[..16].as_ref());
        Ok(())
    }
}

impl<M> Envelope<&[u8], M>
where
    M: LenseView,
{
    /// Check the message authentication code
    pub fn check_seal(&self, srv: &CryptoServer) -> CryptoServerResult<bool> {
        let expected = lprf::mac()?.mix(srv.spkm.secret())?.mix(self.until_mac())?;
        Ok(rosenpass_sodium::helpers::memcmp(
            self.mac(),
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
        }
    }
}

impl HandshakeState {
    pub fn zero() -> Self {
        Self {
            sidi: SessionId::zero(),
            sidr: SessionId::zero(),
            ck: SecretPrfTree::zero().dup(),
        }
    }

    pub fn erase(&mut self) {
        self.ck = SecretPrfTree::zero().dup();
    }

    pub fn init(&mut self, spkr: &[u8]) -> CryptoServerResult<&mut Self> {
        self.ck = lprf::ckinit()?.mix(spkr)?.into_secret_prf_tree().dup();
        Ok(self)
    }

    pub fn mix(&mut self, a: &[u8]) -> Result<&mut Self> {
        self.ck = self.ck.mix(&lprf::mix()?)?.mix(a)?.dup();
        Ok(self)
    }

    pub fn encrypt_and_mix(&mut self, ct: &mut [u8], pt: &[u8]) -> CryptoServerResult<&mut Self> {
        let k = self.ck.mix(&lprf::hs_enc()?)?.into_secret();
        aead::encrypt(ct, k.secret(), &[0u8; aead::NONCE_LEN], &[], pt)?;
        self.mix(ct)
    }

    pub fn decrypt_and_mix(&mut self, pt: &mut [u8], ct: &[u8]) -> CryptoServerResult<&mut Self> {
        let k = self.ck.mix(&lprf::hs_enc()?)?.into_secret();
        aead::decrypt(pt, k.secret(), &[0u8; aead::NONCE_LEN], &[], ct)?;
        self.mix(ct)
    }

    // I loathe "error: constant expression depends on a generic parameter"
    pub fn encaps_and_mix<T: KEM, const SHK_LEN: usize>(
        &mut self,
        ct: &mut [u8],
        pk: &[u8],
    ) -> CryptoServerResult<&mut Self> {
        let mut shk = Secret::<SHK_LEN>::zero();
        T::encaps(shk.secret_mut(), ct, pk)?;
        self.mix(pk)?.mix(shk.secret())?.mix(ct)
    }

    pub fn decaps_and_mix<T: KEM, const SHK_LEN: usize>(
        &mut self,
        sk: &[u8],
        pk: &[u8],
        ct: &[u8],
    ) -> CryptoServerResult<&mut Self> {
        let mut shk = Secret::<SHK_LEN>::zero();
        T::decaps(shk.secret_mut(), sk, ct)?;
        self.mix(pk)?.mix(shk.secret())?.mix(ct)
    }

    pub fn store_biscuit(
        &mut self,
        srv: &mut CryptoServer,
        peer: PeerPtr,
        biscuit_ct: &mut [u8],
    ) -> CryptoServerResult<&mut Self> {
        let mut biscuit = Secret::<BISCUIT_PT_LEN>::zero(); // pt buffer
        let mut biscuit = (&mut biscuit.secret_mut()[..]).biscuit()?; // lens view

        // calculate pt contents
        biscuit
            .pidi_mut()
            .copy_from_slice(peer.get(srv).pidt()?.as_slice());
        biscuit.biscuit_no_mut().copy_from_slice(&*srv.biscuit_ctr);
        biscuit
            .ck_mut()
            .copy_from_slice(self.ck.clone().danger_into_secret().secret());

        // calculate ad contents
        let ad = lprf::biscuit_ad()?
            .mix(srv.spkm.secret())?
            .mix(self.sidi.as_slice())?
            .mix(self.sidr.as_slice())?
            .into_value();

        // consume biscuit no
        rosenpass_sodium::helpers::increment(&mut *srv.biscuit_ctr);

        // The first bit of the nonce indicates which biscuit key was used
        // TODO: This is premature optimization. Remove!
        let bk = srv.active_biscuit_key();
        let mut n = XAEADNonce::random();
        n[0] &= 0b0111_1111;
        n[0] |= (bk.0 as u8 & 0x1) << 7;

        let k = bk.get(srv).key.secret();
        let pt = biscuit.all_bytes();
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
    ) -> CryptoServerResult<(PeerPtr, BiscuitId, HandshakeState)> {
        // The first bit of the biscuit indicates which biscuit key was used
        let bk = BiscuitKeyPtr(((biscuit_ct[0] & 0b1000_0000) >> 7) as usize);

        // Calculate additional data fields
        let ad = lprf::biscuit_ad()?
            .mix(srv.spkm.secret())?
            .mix(sidi.as_slice())?
            .mix(sidr.as_slice())?
            .into_value();

        // Allocate and decrypt the biscuit data
        let mut biscuit = Secret::<BISCUIT_PT_LEN>::zero(); // pt buf
        let mut biscuit = (&mut biscuit.secret_mut()[..]).biscuit()?; // slice
        xaead::decrypt(
            biscuit.all_bytes_mut(),
            bk.get(srv).key.secret(),
            &ad,
            biscuit_ct,
        )?;

        // Reconstruct the biscuit fields
        let no = BiscuitId::from_slice(biscuit.biscuit_no());
        let ck = SecretPrfTree::danger_from_secret(Secret::from_slice(biscuit.ck())).dup();
        let pid = PeerId::from_slice(biscuit.pidi());

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
            rosenpass_sodium::helpers::compare(biscuit.biscuit_no(), &*peer.get(srv).biscuit_used)
                >= 0,
            "Rejecting biscuit: Outdated biscuit number"
        );

        Ok((peer, no, hs))
    }

    pub fn enter_live(self, srv: &CryptoServer, role: HandshakeRole) -> CryptoServerResult<Session> {
        let HandshakeState { ck, sidi, sidr } = self;
        let tki = ck.mix(&lprf::ini_enc()?)?.into_secret();
        let tkr = ck.mix(&lprf::res_enc()?)?.into_secret();
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
    pub fn osk(&self, peer: PeerPtr) -> CryptoServerResult<SymKey> {
        let session = peer
            .session()
            .get(self)
            .as_ref()
            .with_context(|| format!("No current session for peer {:?}", peer))?;
        Ok(session.ck.mix(&lprf::osk()?)?.into_secret())
    }
}

impl CryptoServer {
    /// Implementation of the cryptographic protocol using the already
    /// established primitives
    pub fn handle_initiation(
        &mut self,
        peer: PeerPtr,
        mut ih: InitHello<&mut [u8]>,
    ) -> CryptoServerResult<PeerPtr> {
        let mut hs = InitiatorHandshake::zero_with_timestamp(self);

        // IHI1
        hs.core.init(peer.get(self).spkt.secret())?;

        // IHI2
        hs.core.sidi.randomize();
        ih.sidi_mut().copy_from_slice(&hs.core.sidi.value);

        // IHI3
        EphemeralKEM::keygen(hs.eski.secret_mut(), &mut *hs.epki)?;
        ih.epki_mut().copy_from_slice(&hs.epki.value);

        // IHI4
        hs.core.mix(ih.sidi())?.mix(ih.epki())?;

        // IHI5
        hs.core
            .encaps_and_mix::<StaticKEM, { StaticKEM::SHK_LEN }>(
                ih.sctr_mut(),
                peer.get(self).spkt.secret(),
            )?;

        // IHI6
        hs.core
            .encrypt_and_mix(ih.pidic_mut(), self.pidm()?.as_ref())?;

        // IHI7
        hs.core
            .mix(self.spkm.secret())?
            .mix(peer.get(self).psk.secret())?;

        // IHI8
        hs.core.encrypt_and_mix(ih.auth_mut(), &[])?;

        // Update the handshake hash last (not changing any state on prior error
        peer.hs().insert(self, hs)?;

        Ok(peer)
    }

    pub fn handle_init_hello(
        &mut self,
        ih: InitHello<&[u8]>,
        mut rh: RespHello<&mut [u8]>,
    ) -> CryptoServerResult<PeerPtr> {
        let mut core = HandshakeState::zero();

        core.sidi = SessionId::from_slice(ih.sidi());

        // IHR1
        core.init(self.spkm.secret())?;

        // IHR4
        core.mix(ih.sidi())?.mix(ih.epki())?;

        // IHR5
        core.decaps_and_mix::<StaticKEM, { StaticKEM::SHK_LEN }>(
            self.sskm.secret(),
            self.spkm.secret(),
            ih.sctr(),
        )?;

        // IHR6
        let peer = {
            let mut peerid = PeerId::zero();
            core.decrypt_and_mix(&mut *peerid, ih.pidic())?;
            self.find_peer(peerid)
                .with_context(|| format!("No such peer {peerid:?}."))?
        };

        // IHR7
        core.mix(peer.get(self).spkt.secret())?
            .mix(peer.get(self).psk.secret())?;

        // IHR8
        core.decrypt_and_mix(&mut [0u8; 0], ih.auth())?;

        // RHR1
        core.sidr.randomize();
        rh.sidi_mut().copy_from_slice(core.sidi.as_ref());
        rh.sidr_mut().copy_from_slice(core.sidr.as_ref());

        // RHR3
        core.mix(rh.sidr())?.mix(rh.sidi())?;

        // RHR4
        core.encaps_and_mix::<EphemeralKEM, { EphemeralKEM::SHK_LEN }>(rh.ecti_mut(), ih.epki())?;

        // RHR5
        core.encaps_and_mix::<StaticKEM, { StaticKEM::SHK_LEN }>(
            rh.scti_mut(),
            peer.get(self).spkt.secret(),
        )?;

        // RHR6
        core.store_biscuit(self, peer, rh.biscuit_mut())?;

        // RHR7
        core.encrypt_and_mix(rh.auth_mut(), &[])?;

        Ok(peer)
    }

    pub fn handle_resp_hello(
        &mut self,
        rh: RespHello<&[u8]>,
        mut ic: InitConf<&mut [u8]>,
    ) -> CryptoServerResult<PeerPtr> {
        // RHI2
        let peer = self
            .lookup_handshake(SessionId::from_slice(rh.sidi()))
            .with_context(|| {
                format!(
                    "Got RespHello packet for non-existent session {:?}",
                    rh.sidi()
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
            SessionId::from_slice(rh.sidi()),
            exp,
            got
        );

        let mut core = hs!().core.clone();
        core.sidr.copy_from_slice(rh.sidr());

        // TODO: decaps_and_mix should take Secret<> directly
        //       to save us from the repetitive secret unwrapping

        // RHI3
        core.mix(rh.sidr())?.mix(rh.sidi())?;

        // RHI4
        core.decaps_and_mix::<EphemeralKEM, { EphemeralKEM::SHK_LEN }>(
            hs!().eski.secret(),
            &*hs!().epki,
            rh.ecti(),
        )?;

        // RHI5
        core.decaps_and_mix::<StaticKEM, { StaticKEM::SHK_LEN }>(
            self.sskm.secret(),
            self.spkm.secret(),
            rh.scti(),
        )?;

        // RHI6
        core.mix(rh.biscuit())?;

        // RHI7
        core.decrypt_and_mix(&mut [0u8; 0], rh.auth())?;

        // TODO: We should just authenticate the entire network package up to the auth
        // tag as a pattern instead of mixing in fields separately

        ic.sidi_mut().copy_from_slice(rh.sidi());
        ic.sidr_mut().copy_from_slice(rh.sidr());

        // ICI3
        core.mix(ic.sidi())?.mix(ic.sidr())?;
        ic.biscuit_mut().copy_from_slice(rh.biscuit());

        // ICI4
        core.encrypt_and_mix(ic.auth_mut(), &[])?;

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
        ic: InitConf<&[u8]>,
        mut rc: EmptyData<&mut [u8]>,
    ) -> CryptoServerResult<PeerPtr> {
        // (peer, bn) ← LoadBiscuit(InitConf.biscuit)
        // ICR1
        let (peer, biscuit_no, mut core) = HandshakeState::load_biscuit(
            self,
            ic.biscuit(),
            SessionId::from_slice(ic.sidi()),
            SessionId::from_slice(ic.sidr()),
        )?;

        // ICR2
        core.encrypt_and_mix(&mut [0u8; aead::TAG_LEN], &[])?;

        // ICR3
        core.mix(ic.sidi())?.mix(ic.sidr())?;

        // ICR4
        core.decrypt_and_mix(&mut [0u8; 0], ic.auth())?;

        // ICR5
        if rosenpass_sodium::helpers::compare(&*biscuit_no, &*peer.get(self).biscuit_used) > 0 {
            // ICR6
            peer.get_mut(self).biscuit_used = biscuit_no;

            // ICR7
            peer.session()
                .insert(self, core.enter_live(self, HandshakeRole::Responder)?)?;
            // TODO: This should be part of the protocol specification.
            // Abort any ongoing handshake from initiator role
            peer.hs().take(self);
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
        return Err(CryptoServerError::CustomError("Cannot send acknowledgement. No session.".to_string()));
        rc.sid_mut().copy_from_slice(&ses.sidt.value);
        rc.ctr_mut().copy_from_slice(&ses.txnm.to_le_bytes());
        ses.txnm += 1; // Increment nonce before encryption, just in case an error is raised

        let n = cat!(aead::NONCE_LEN; rc.ctr(), &[0u8; 4]);
        let k = ses.txkm.secret();
        aead::encrypt(rc.auth_mut(), k, &n, &[], &[])?; // ct, k, n, ad, pt

        Ok(peer)
    }

    pub fn handle_resp_conf(&mut self, rc: EmptyData<&[u8]>) -> CryptoServerResult<PeerPtr> {
        let sid = SessionId::from_slice(rc.sid());
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
            let n = u64::from_le_bytes(rc.ctr().try_into().unwrap());
            ensure!(n >= s.txnt, "Stale nonce");
            s.txnt = n;
            aead::decrypt(
                // pt, k, n, ad, ct
                &mut [0u8; 0],
                s.txkt.secret(),
                &cat!(aead::NONCE_LEN; rc.ctr(), &[0u8; 4]),
                &[],
                rc.auth(),
            )?;
        }

        // We can now stop retransmitting RespConf
        hs.take(self);

        Ok(hs.peer())
    }
}

#[cfg(test)]
mod test {
    use super::*;

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
        rosenpass_sodium::init().unwrap();

        stacker::grow(8 * 1024 * 1024, || {
            const OVERSIZED_MESSAGE: usize = ((MAX_MESSAGE_LEN as f32) * 1.2) as usize;
            type MsgBufPlus = Public<OVERSIZED_MESSAGE>;

            const PEER0: PeerPtr = PeerPtr(0);

            let (mut me, mut they) = make_server_pair().unwrap();
            let (mut msgbuf, mut resbuf) = (MsgBufPlus::zero(), MsgBufPlus::zero());

            // Process the entire handshake
            let mut msglen = Some(me.initiate_handshake(PEER0, &mut *resbuf).unwrap());
            loop {
                if let Some(l) = msglen {
                    std::mem::swap(&mut me, &mut they);
                    std::mem::swap(&mut msgbuf, &mut resbuf);
                    msglen = test_incorrect_sizes_for_msg(&mut me, &*msgbuf, l, &mut *resbuf);
                } else {
                    break;
                }
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
            assert!(matches!(res, Err(_))); // handle_msg should raise an error
            assert!(!resbuf.iter().find(|x| **x != 0).is_some()); // resbuf should not have been changed
        }

        // Apply the proper handle_msg operation
        srv.handle_msg(&msgbuf[..msglen], resbuf).unwrap().resp
    }

    fn keygen() -> CryptoServerResult<(SSk, SPk)> {
        // TODO: Copied from the benchmark; deduplicate
        let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
        StaticKEM::keygen(sk.secret_mut(), pk.secret_mut())?;
        Ok((sk, pk))
    }

    fn make_server_pair() -> CryptoServerResult<(CryptoServer, CryptoServer)> {
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
}
