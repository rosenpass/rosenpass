//! This module is a left-over from when [crate::protocol] was a monolithic file.
//!
//! It is merged entirely into [crate::protocol] and should be split up into multiple
//! files.

use std::collections::hash_map::{
    Entry::{Occupied, Vacant},
    HashMap,
};
use std::{
    borrow::Borrow,
    fmt::{Debug, Display},
    mem::size_of,
    ops::Deref,
};

use anyhow::{bail, ensure, Context, Result};
use memoffset::span_of;
use zerocopy::{AsBytes, FromBytes, Ref};

use rosenpass_cipher_traits::primitives::{
    Aead as _, AeadWithNonceInCiphertext, Kem, KeyedHashInstance,
};
use rosenpass_ciphers::hash_domain::{SecretHashDomain, SecretHashDomainNamespace};
use rosenpass_ciphers::{Aead, EphemeralKem, KeyedHash, StaticKem, XAead};
use rosenpass_constant_time as constant_time;
use rosenpass_secret_memory::{Public, Secret};
use rosenpass_to::{ops::copy_slice, To};
use rosenpass_util::{
    cat,
    functional::ApplyExt,
    mem::{cpy_min, DiscardResultExt},
    time::Timebase,
};

use crate::{hash_domains, msgs::*, RosenpassError};

use super::basic_types::{
    BiscuitId, EPk, ESk, MsgBuf, PeerId, PeerNo, PublicSymKey, SPk, SSk, SessionId, SymKey,
    XAEADNonce,
};
use super::constants::{
    BISCUIT_EPOCH, COOKIE_SECRET_EPOCH, COOKIE_SECRET_LEN, COOKIE_VALUE_LEN,
    PEER_COOKIE_VALUE_EPOCH, REJECT_AFTER_TIME, REKEY_AFTER_TIME_INITIATOR,
    REKEY_AFTER_TIME_RESPONDER, RETRANSMIT_DELAY_BEGIN, RETRANSMIT_DELAY_END,
    RETRANSMIT_DELAY_GROWTH, RETRANSMIT_DELAY_JITTER,
};
use super::cookies::{BiscuitKey, CookieSecret, CookieStore};
use super::index::{PeerIndex, PeerIndexKey};
use super::osk_domain_separator::OskDomainSeparator;
use super::timing::{has_happened, Timing, BCE, UNENDING};
use super::zerocopy::{truncating_cast_into, truncating_cast_into_nomut};

#[cfg(feature = "trace_bench")]
use rosenpass_util::trace_bench::Trace as _;

// DATA STRUCTURES & BASIC TRAITS & ACCESSORS ////
/// This is the implementation of our cryptographic protocol.
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
///
///
///
/// # Example
///
/// See the example on how to use this CryptoServer without [Self::poll] in [crate::protocol].
///
/// See [Self::poll] on how to use a CryptoServer with poll.
#[derive(Debug)]
pub struct CryptoServer {
    /// The source of most timing information for the Rosenpass protocol
    ///
    /// We store most timing information in the form of f64 values, relative to a point stored in
    /// this field.
    pub timebase: Timebase,

    /// Static Secret Key Mine (our secret key)
    pub sskm: SSk,
    /// Static Public Key Mine (our public key)
    pub spkm: SPk,
    /// Counter used to fill the [Biscuit::biscuit_no] field for biscuits issued.
    ///
    /// Every [Biscuit] issued contains a biscuit number; this is the counter used to generate
    /// the biscuit number.
    ///
    /// See [HandshakeState::store_biscuit] and [HandshakeState::load_biscuit]
    pub biscuit_ctr: BiscuitId,
    /// Every [Biscuit] issued is encrypted before being transmitted to the initiator.
    ///
    /// The biscuit key used is rotated every [BISCUIT_EPOCH]. We store the previous
    /// biscuit key for decryption only.
    ///
    /// See [HandshakeState::store_biscuit], [HandshakeState::load_biscuit], and
    /// [CryptoServer::active_biscuit_key].
    pub biscuit_keys: [BiscuitKey; 2],

    /// List of peers and their session and handshake states
    pub peers: Vec<Peer>,
    /// Index into the list of peers. See [PeerIndexKey] for details.
    pub index: PeerIndex,
    /// Hash key for known responder confirmation responses.
    ///
    /// These hashes are then used for lookups in [Self::index] using
    /// the [PeerIndexKey::KnownInitConfResponse] enum case.
    ///
    /// This is used to allow for retransmission of responder confirmation (i.e.
    /// [Envelope]<[EmptyData]>) messages in response to [Envelope]<[InitConf]>
    /// without involving the cryptographic layer.
    ///
    /// See [KnownResponse], [KnownInitConfResponse], [KnownInitConfResponsePtr],
    /// and the [whitepaper](https://rosenpass.eu/whitepaper.pdf)
    pub known_response_hasher: KnownResponseHasher,

    /// We poll peers in a round-robin fashion, but we can not poll
    /// all peers in one go. If one of them returns a result, [CryptoServer::poll]
    /// will return the particular peer's event.
    ///
    /// This value makes sure we start polling with the next peer on the next [CryptoServer::poll]
    /// call.
    ///
    /// See [CryptoServer::poll], [CryptoServer::peer_ptrs_off].
    pub peer_poll_off: usize,

    /// Cookies issued for the purpose of DOS mitigations are derived from a
    /// secret key. This field stores those secret keys.
    ///
    /// The value is rotated every [COOKIE_SECRET_EPOCH].
    ///
    /// See [CryptoServer::handle_msg_under_load], and [CryptoServer::active_or_retired_cookie_secrets].
    pub cookie_secrets: [CookieSecret; 2],
}

/// Specifies the protocol version used by a peer.
#[derive(Debug, Clone)]
pub enum ProtocolVersion {
    V02,
    V03,
}

impl ProtocolVersion {
    /// Returns the [KeyedHash] used by a protocol version.
    pub fn keyed_hash(&self) -> KeyedHash {
        match self {
            ProtocolVersion::V02 => KeyedHash::incorrect_hmac_blake2b(),
            ProtocolVersion::V03 => KeyedHash::keyed_shake256(),
        }
    }
}

impl From<crate::config::ProtocolVersion> for ProtocolVersion {
    fn from(v: crate::config::ProtocolVersion) -> Self {
        match v {
            crate::config::ProtocolVersion::V02 => ProtocolVersion::V02,
            crate::config::ProtocolVersion::V03 => ProtocolVersion::V03,
        }
    }
}

/// A peer that the server can execute a key exchange with.
///
/// Peers generally live in [CryptoServer::peers]. [PeerNo] captures an array
/// into this field and [PeerPtr] is a wrapper around a [PeerNo] imbued with
/// peer specific functionality. [CryptoServer::index] contains a list of lookup-keys
/// for retrieving peers using various keys (see [PeerIndexKey]).
///
/// # Examples
///
/// ```
/// use std::ops::DerefMut;
///
/// use rosenpass_ciphers::StaticKem;
/// use rosenpass_cipher_traits::primitives::Kem;
///
/// use rosenpass::protocol::basic_types::{SSk, SPk, SymKey};
/// use rosenpass::protocol::{Peer, ProtocolVersion};
/// use rosenpass::protocol::osk_domain_separator::OskDomainSeparator;
///
/// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
///
/// let (mut sskt, mut spkt) = (SSk::zero(), SPk::zero());
/// StaticKem.keygen(sskt.secret_mut(), spkt.deref_mut())?;
///
/// let (mut sskt2, mut spkt2) = (SSk::zero(), SPk::zero());
/// StaticKem.keygen(sskt2.secret_mut(), spkt2.deref_mut())?;
///
/// let psk = SymKey::random();
///
/// // Creation with a PSK
/// let peer_psk = Peer::new(psk, spkt.clone(), ProtocolVersion::V03, OskDomainSeparator::default());
///
/// // Creation without a PSK
/// let peer_nopsk = Peer::new(SymKey::zero(), spkt, ProtocolVersion::V03, OskDomainSeparator::default());
///
/// // Create a second peer
/// let peer_psk_2 = Peer::new(SymKey::zero(), spkt2, ProtocolVersion::V03, OskDomainSeparator::default());
///
/// // Peer ID does not depend on PSK, but it does depend on the public key
/// assert_eq!(peer_psk.pidt()?, peer_nopsk.pidt()?);
/// assert_ne!(peer_psk.pidt()?, peer_psk_2.pidt()?);
///
/// Ok::<(), anyhow::Error>(())
/// ```
#[derive(Debug)]
pub struct Peer {
    /// The pre-shared key shared with the peer.
    ///
    /// This is a symmetric key generated by the user upon setting up a peer.
    /// It must be shared with both peers who wish to exchange keys.
    ///
    /// The Rosenpass protocol is secure if the pre-shared key was generated securely
    /// and is known only to both peers, even if the peers secret keys are leaked or if
    /// the asymmetric cryptographic algorithms are broken.
    pub psk: SymKey,
    /// Static Public Key Theirs. This is the peer's public key.
    pub spkt: SPk,
    /// The biscuit number ([Biscuit::biscuit_no]) last used during reception of a
    /// [Biscuit] inside of a [InitConf] message.
    ///
    /// This field's job is to make sure that [CryptoServer::handle_init_conf] will never
    /// accept the same biscuit twice; i.e. it is used to protect against [InitConf] replay
    /// attacks.
    pub biscuit_used: BiscuitId,
    /// The last established session
    ///
    /// This is indexed though [PeerIndexKey::Sid].
    pub session: Option<Session>,
    /// Ongoing handshake, in initiator mode.
    ///
    /// There is no field for storing handshakes from the responder perspective,
    /// because the state is stored inside a [Biscuit] to make sure the responder
    /// is stateless.
    ///
    /// This is indexed though [PeerIndexKey::Sid].
    pub handshake: Option<InitiatorHandshake>,
    /// Used to make sure that the same [PollResult::SendInitiation] event is never issued twice.
    ///
    /// [CryptoServer::poll] will not produce a [InitHello] message, i.e. call
    /// [CryptoServer::initiate_handshake] (and by proxy [CryptoServer::handle_initiation]),
    /// on its own accord. Instead, it will issue a
    pub initiation_requested: bool,
    /// Stores a known response for a [Envelope]<[InitConf]> message, i.e. a
    /// [Envelope]<[EmptyData]>.
    ///
    /// Upon reception of an InitConf message, [CryptoServer::handle_msg] first checks
    /// if a cached response exists through [PeerIndexKey::KnownInitConfResponse]. If one exists,
    /// then this field must be set to [Option::Some] and the cached response is returned.
    ///
    /// This allows us to perform retransmission for the purpose of dealing with packet loss
    /// on the network without having to account for it in the cryptographic code itself.
    pub known_init_conf_response: Option<KnownInitConfResponse>,
    /// The protocol version used by with this peer.
    pub protocol_version: ProtocolVersion,
    /// Domain separator for generated OSKs
    pub osk_domain_separator: OskDomainSeparator,
}

impl Peer {
    /// Zero initialize a peer
    ///
    /// This is dirty but allows us to perform easy incremental construction of [Self].
    ///
    /// ```
    /// use rosenpass::protocol::basic_types::{SymKey, SPk};
    /// use rosenpass::protocol::{Peer, ProtocolVersion};
    /// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    /// let p = Peer::zero(ProtocolVersion::V03);
    /// assert_eq!(p.psk.secret(), SymKey::zero().secret());
    /// assert_eq!(p.spkt, SPk::zero());
    /// // etc.
    /// ```
    pub fn zero(protocol_version: ProtocolVersion) -> Self {
        Self {
            psk: SymKey::zero(),
            spkt: SPk::zero(),
            biscuit_used: BiscuitId::zero(),
            session: None,
            initiation_requested: false,
            handshake: None,
            known_init_conf_response: None,
            protocol_version,
            osk_domain_separator: OskDomainSeparator::default(),
        }
    }
}

/// This represents the core state of an ongoing handshake.
///
/// The responder is stateless, storing its state in a [Biscuit] inside [RespHello]
/// and [InitConf] respective. The initiator wraps this in [InitiatorHandshake].
///
/// # Examples
///
/// The best way to understand how the handshake state is used is to study how they are used
/// in the protocol. Read the source code of
///
/// - [CryptoServer::handle_initiation]
/// - [CryptoServer::handle_init_hello]
/// - [CryptoServer::handle_resp_hello]
/// - [CryptoServer::handle_init_conf]
/// - [CryptoServer::handle_resp_conf]
#[derive(Debug, Clone)]
pub struct HandshakeState {
    /// Session ID of Initiator
    pub sidi: SessionId,
    /// Session ID of Responder
    pub sidr: SessionId,
    /// Chaining Key; i.e. the core cryptographic state
    pub ck: SecretHashDomainNamespace, // TODO: We should probably add an abstr
}

/// Indicates which role a party takes (or took) during the handshake
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug, Copy, Clone)]
pub enum HandshakeRole {
    /// The party was the initiator
    Initiator,
    /// The party was the responder
    Responder,
}

impl HandshakeRole {
    /// Check if the value of this enum is [HandshakeRole::Initiator]
    ///
    /// ```
    /// use rosenpass::protocol::HandshakeRole;
    /// assert!(HandshakeRole::Initiator.is_initiator());
    /// assert!(!HandshakeRole::Responder.is_initiator());
    /// ```
    pub fn is_initiator(&self) -> bool {
        match *self {
            HandshakeRole::Initiator => true,
            HandshakeRole::Responder => false,
        }
    }
}

/// Used in [InitiatorHandshake] to keep track of which packet type
/// is expected next.
#[derive(Copy, Clone, Default, Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum HandshakeStateMachine {
    /// Expecting [RespHello]
    #[default]
    RespHello,
    /// Expecting responder confirmation (i.e. [EmptyData])
    RespConf,
}

/// Stores all the information an initiator requires to
/// perform its handshake.
///
/// The protocol is deliberately designed to minimize responder state
/// even at the expense of increased initiator state, because the
/// responder is stateless and stores its state in a [Biscuit] between
/// inside [RespHello] and [InitConf] respectively.
#[derive(Debug)]
pub struct InitiatorHandshake {
    /// The time the handshake was created at
    pub created_at: Timing,
    /// The package type expected next from the responder
    pub next: HandshakeStateMachine,
    /// The core cryptographic data from the handshake
    pub core: HandshakeState,
    /// Ephemeral Secret Key Initiator; secret key of the ephemeral keypair
    pub eski: ESk,
    /// Ephemeral Public Key Initiator; public key of the ephemeral keypair
    pub epki: EPk,

    /// Unused; TODO: Remove
    pub tx_at: Timing,
    /// Retransmit the package in [Self::tx_buf] at this point in time
    pub tx_retry_at: Timing,
    /// Number of times this message has been retransmitted
    pub tx_count: usize,
    /// Size of the message inside [Self::tx_buf]
    pub tx_len: usize,
    /// The message that should be retransmitted
    pub tx_buf: MsgBuf,

    /// Cookie value used as part of the cookie retransmission mechanism.
    ///
    /// See the [whitepaper](https://rosenpass.eu/whitepaper.pdf) for details about the cookie
    /// mechanism.
    ///
    /// TODO: cookie_value should be an Option<_>
    /// TODO: This should not use CookieStore, which exists to store randomly generated cookie
    /// secrets
    ///
    /// This value seems to default-initialized with a random value according to
    /// [Self::zero_with_timestamp], which does not really make sense since this
    /// is not a value that the responder sets. We also seem to use the cookie
    /// value unconditionally (see [Envelope::seal]). This is not harmful as the
    /// responder ignores the cookie field by default, but it is quite odd.
    /// We should check the WireGuard whitepaper about which default value WireGuard
    /// uses for the cookie values and potentially leave the cookie field empty by
    /// default.
    pub cookie_value: CookieStore<COOKIE_VALUE_LEN>,
}

/// Represents a known response to some network message identified by
/// the hash in [Self::request_mac].
///
/// Used as [KnownInitConfResponse] for now cache [EmptyData] (responder confirmation)
/// responses to [InitConf]
pub struct KnownResponse<ResponseType: AsBytes + FromBytes> {
    /// When the response was initially computed
    pub received_at: Timing,
    /// Hash of the message that triggered the response; created using
    /// the key in [CryptoServer::known_response_hasher]
    pub request_mac: KnownResponseHash,
    /// The cached response
    pub response: Envelope<ResponseType>,
}

impl<ResponseType: AsBytes + FromBytes> Debug for KnownResponse<ResponseType> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KnownResponse")
            .field("received_at", &self.received_at)
            .field("request_mac", &self.request_mac)
            .field("response", &"...")
            .finish()
    }
}

#[test]
fn known_response_format() {
    use zerocopy::FromZeroes;

    let v = KnownResponse::<[u8; 32]> {
        received_at: 42.0,
        request_mac: Public::zero(),
        response: Envelope::new_zeroed(),
    };
    let s = format!("{v:?}");
    assert!(s.contains("response")); // Smoke test only, it's a formatter
}

/// Known [EmptyData] response to an [InitConf] message
///
/// See [Peer::known_init_conf_response]
pub type KnownInitConfResponse = KnownResponse<EmptyData>;

/// The type used to represent the hash of a known response
/// in the context of [KnownResponse]/[PeerIndexKey::KnownInitConfResponse]
pub type KnownResponseHash = Public<16>;

/// Object that produces [KnownResponseHash].
///
/// Merely a key plus some utility functions.
///
/// See [PeerIndexKey::KnownInitConfResponse] and [KnownResponse::request_mac]
///
/// # Examples
///
/// ```
/// use zerocopy::FromZeroes;
/// use rosenpass::protocol::KnownResponseHasher;
/// use rosenpass::msgs::{Envelope, InitConf};
///
/// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
///
/// let h = KnownResponseHasher::new();
///
/// let v1 = Envelope::<InitConf>::new_zeroed();
///
/// let mut v2 = Envelope::<InitConf>::new_zeroed();
/// assert_eq!(h.hash(&v1), h.hash(&v2));
///
/// v2.msg_type = 1;
/// assert_ne!(h.hash(&v1), h.hash(&v2));
/// ```
#[derive(Debug)]
pub struct KnownResponseHasher {
    /// The key used for hashing   
    pub key: SymKey,
}

impl KnownResponseHasher {
    /// Construct a new hasher with a random key
    ///
    /// # Examples
    ///
    /// See [Self]
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            key: SymKey::random(),
        }
    }

    /// Hash a message
    ///
    /// # Examples
    ///
    /// See [Self]
    ///
    /// # Panic & Safety
    ///
    /// Panics in case of a problem with this underlying hash function
    pub fn hash<Msg: AsBytes + FromBytes>(&self, msg: &Envelope<Msg>) -> KnownResponseHash {
        let data = &msg.as_bytes()[span_of!(Envelope<Msg>, msg_type..cookie)];
        // This function is only used internally and results are not propagated
        // to outside the peer. Thus, it uses SHAKE256 exclusively.
        let mut hash = [0u8; 32];
        KeyedHash::keyed_shake256()
            .keyed_hash(self.key.secret(), data, &mut hash)
            .unwrap();
        Public::from_slice(&hash[0..16]) // truncate to 16 bytes
    }
}

/// An established session
///
/// Rosenpass is a key exchange and not transport protocol
/// though initially we still though Rosenpass might be expanded
/// into a transport protocol at some point. These plans are not
/// entirely abandoned, but if we do decide that Rosenpass should
/// support transport encryption then we will add this as a protocol
/// extension. For this reason, Rosenpass currently essentially features
/// stubs for transport data handling (and therefor session handling)
/// but they are not really put to good use; the session implementation
/// is overcomplicated for what we really use.
///
/// Session encryption is used exclusively to transmit [EmptyData] which
/// tells the initiator to abort retransmission of [InitConf].
///
/// The session is also used to keep track of when a key renegotiation
/// needs to happen; see [PeerPtr::poll].
#[derive(Debug)]
pub struct Session {
    /// When the session was created
    pub created_at: Timing,
    /// Session ID Mine; Our session ID
    pub sidm: SessionId,
    /// Session ID Theirs; Peer's session ID
    pub sidt: SessionId,
    /// Whether we where the initiator or responder during the handshake
    /// (affects when we begin another initiation; by default, the initiator
    /// waits a bit longer, allowing role switching)
    pub handshake_role: HandshakeRole,
    /// Cryptographic key produced by the handshake
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

/// Lifecycle of a value
///
/// For secret keys whose life cycle is managed using this struct,
/// we impose very particular semantics: The order implies the readiness for usage of a secret, the highest/biggest
/// variant ([Lifecycle::Young]) is the most preferable one in a class of
/// equal-role secrets.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Lifecycle {
    /// Empty value
    Void = 0,
    /// The value should be deleted.
    ///
    /// If a secret, it must be zeroized and disposed.
    Dead,
    /// Soon to be dead. Do not use anymore.
    ///
    /// If a secret, it might be used for decoding (decrypting)
    /// data, but must not be used for encryption of cryptographic values.
    Retired,
    /// The value is fresh and in active use.
    ///
    /// If a secret, it might be used unconditionally; in particular, the secret
    /// can be used for the encoding (encryption) of cryptographic values.
    Young,
}

/// Life cycle management for values
///
/// # Examples
///
/// See [MortalExt]
pub trait Mortal {
    /// Time of creation, when [Lifecycle::Void] -> [Lifecycle::Young]
    ///
    /// # Examples
    ///
    /// See [MortalExt]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing>;
    /// The time where [Lifecycle::Young] -> [Lifecycle::Retired]
    ///
    /// # Examples
    ///
    /// See [MortalExt]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing>;
    /// The time where [Lifecycle::Retired] -> [Lifecycle::Dead]
    ///
    /// # Examples
    ///
    /// See [MortalExt]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing>;
}

// BUSINESS LOGIC DATA STRUCTURES ////////////////

/// Valid index to [CryptoServer::peers], focusing on the peer itself.
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the peer but require access to the [CryptoServer].
///
/// # Examples
///
/// ```
/// use std::ops::DerefMut;
/// use rosenpass_ciphers::StaticKem;
/// use rosenpass::protocol::basic_types::{SSk, SPk};
/// use rosenpass::protocol::{testutils::ServerForTesting, ProtocolVersion};
///
/// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
///
/// let (peer, (_, spkt), mut srv) = ServerForTesting::new(ProtocolVersion::V03)?.tuple();
///
/// // Immutable access
/// assert_eq!(peer.get(&srv).spkt, spkt);
///
/// // Mutable access
/// peer.get_mut(&mut srv).initiation_requested = true;
/// assert!(peer.get(&srv).initiation_requested);
///
/// // Produce a session pointer for the particular peer
/// assert!(peer.session().get(&srv).is_none());
/// assert!(peer.session().get_mut(&mut srv).is_none());
///
/// // Produce a handshake pointer for the particular peer
/// assert!(peer.hs().get(&srv).is_none());
/// assert!(peer.hs().get_mut(&mut srv).is_none());
///
/// // Produce a cookie value pointer for the particular peer
/// assert!(peer.cv().get(&srv).is_none());
///
/// // The mutable getter for cookie values is a bit special;
/// // instead of getting access to the container value, you are
/// // given direct acccess to the underlying buffer. If the value
/// // is present; the function also updates the cookie value's
/// // `created_at` value.
/// // Though in this example, update_mut simply returns none.
/// assert!(peer.cv().update_mut(&mut srv).is_none());
///
/// // Produce a known init conf response pointer for the particular peer
/// assert!(peer.known_init_conf_response().get(&srv).is_none());
/// assert!(peer.known_init_conf_response().get_mut(&mut srv).is_none());
///
/// // All the sub-pointers generally implement functions to get back to the
/// // peer that contains them
/// assert_eq!(peer.session().peer(), peer);
/// assert_eq!(peer.hs().peer(), peer);
/// //assert_eq!(peer.cv().peer(), peer); // Does not provide a link back right now
/// assert_eq!(peer.known_init_conf_response().peer(), peer);
///
/// Ok::<(), anyhow::Error>(())
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct PeerPtr(pub usize);

/// Valid index to [CryptoServer::peers], focusing on [Peer::handshake].
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the handshake but require access to the [CryptoServer].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct IniHsPtr(pub usize);

/// Valid index to [CryptoServer::peers], focusing on [Peer::session].
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the handshake but require access to the [CryptoServer].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct SessionPtr(pub usize);

/// Valid index to [CryptoServer::peers], focusing on [InitiatorHandshake::cookie_value]
/// inside [Peer::handshake].
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the cookie value but require access to the [CryptoServer].
pub struct PeerCookieValuePtr(usize);

/// Valid index to [CryptoServer::peers], focusing on [Peer::known_init_conf_response].
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the known response value but require access to the [CryptoServer].
pub struct KnownInitConfResponsePtr(PeerNo);

/// Valid index to [CryptoServer::biscuit_keys]
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the biscuit key but require access to the [CryptoServer].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct BiscuitKeyPtr(pub usize);

/// Valid index to [CryptoServer::cookie_secrets]
///
/// Provides appropriate utility functions, especially those that
/// somehow focus on the cookie secret but require access to the [CryptoServer].
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub struct ServerCookieSecretPtr(pub usize);

impl PeerPtr {
    /// Access a peer
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this PeerPtr does not exist.
    ///
    /// # Examples
    ///
    /// See [Self]
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a Peer {
        &srv.peers[self.0]
    }

    /// Mutable access to a peer.
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this PeerPtr does not exist.
    ///
    /// # Examples
    ///
    /// See [Self]
    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut Peer {
        &mut srv.peers[self.0]
    }

    /// Produce pointer to associated session
    ///
    /// # Examples
    ///
    /// See [Self]
    pub fn session(&self) -> SessionPtr {
        SessionPtr(self.0)
    }

    /// Produce pointer to associated handshake
    ///
    /// # Examples
    ///
    /// See [Self]
    pub fn hs(&self) -> IniHsPtr {
        IniHsPtr(self.0)
    }

    /// Produce pointer to associated cookie value
    ///
    /// # Examples
    ///
    /// See [Self]
    pub fn cv(&self) -> PeerCookieValuePtr {
        PeerCookieValuePtr(self.0)
    }

    /// Produce pointer to associated known init conf response
    ///
    /// # Examples
    ///
    /// See [Self]
    pub fn known_init_conf_response(&self) -> KnownInitConfResponsePtr {
        KnownInitConfResponsePtr(self.0)
    }
}

impl IniHsPtr {
    /// Access the handshake value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a Option<InitiatorHandshake> {
        &srv.peers[self.0].handshake
    }

    /// Mutable access to the handshake value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut Option<InitiatorHandshake> {
        &mut srv.peers[self.0].handshake
    }

    /// Access the associated peer
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn peer(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    /// Insert a new handshake into the peer
    ///
    /// Note that this also registers the session with the server ([CryptoServer::register_session]),
    /// so the handshake must be properly initialized. The [HandshakeState::sidi] value (inside
    /// [InitiatorHandshake::core]) is used
    /// to register the handshake in the session index via [CryptoServer::register_session] and the
    /// peer's [Peer::initiation_requested] flag is set to false since any such request was just
    /// acted upon by inserting this handshake.
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
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

    /// Take (remove and return) the current InititiatorHandshake from the peer.
    ///
    /// The handshake is also unregistered from the handshake index by using [CryptoServer::unregister_session_if_vacant].
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    pub fn take(&self, srv: &mut CryptoServer) -> Option<InitiatorHandshake> {
        let r = self.peer().get_mut(srv).handshake.take();
        if let Some(ref stale) = r {
            srv.unregister_session_if_vacant(stale.core.sidi, self.peer());
        }
        r
    }
}

impl SessionPtr {
    /// Access the session value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a Option<Session> {
        &srv.peers[self.0].session
    }

    /// Mutable access to the session value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut Option<Session> {
        &mut srv.peers[self.0].session
    }

    /// Access the associated peer
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn peer(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    /// Insert a new session into the peer
    ///
    /// Note that this also registers the session with the server ([CryptoServer::register_session]),
    /// using [Session::sidm], so the session must be properly initialized.
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    pub fn insert<'a>(&self, srv: &'a mut CryptoServer, ses: Session) -> Result<&'a mut Session> {
        self.take(srv);
        srv.register_session(ses.sidm, self.peer())?;
        Ok(self.peer().get_mut(srv).session.insert(ses))
    }

    /// Take (remove and return) the current Session from the peer.
    ///
    /// The session is also unregistered from the session index by using [CryptoServer::unregister_session_if_vacant].
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    pub fn take(&self, srv: &mut CryptoServer) -> Option<Session> {
        let r = self.peer().get_mut(srv).session.take();
        if let Some(ref stale) = r {
            srv.unregister_session_if_vacant(stale.sidm, self.peer());
        }
        r
    }
}

impl BiscuitKeyPtr {
    /// Access the referenced biscuit key
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a BiscuitKey {
        &srv.biscuit_keys[self.0]
    }

    /// Mutable access to the referenced biscuit key
    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut BiscuitKey {
        &mut srv.biscuit_keys[self.0]
    }
}

impl ServerCookieSecretPtr {
    /// Access the referenced cookie secret
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> &'a CookieSecret {
        &srv.cookie_secrets[self.0]
    }

    /// Mutable access to the referenced cookie secret
    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> &'a mut CookieSecret {
        &mut srv.cookie_secrets[self.0]
    }
}

impl PeerCookieValuePtr {
    /// Access the peer cookie value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> Option<&'a CookieStore<COOKIE_SECRET_LEN>> {
        srv.peers[self.0]
            .handshake
            .as_ref()
            .map(|v| &v.cookie_value)
    }

    /// Direct mutable access the peer cookie value
    ///
    /// Updates the [CookieStore::created_at] value of the cookie value.
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this does not exist.
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
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

impl KnownInitConfResponsePtr {
    /// Access the associated peer
    ///
    /// # Examples
    ///
    /// See [PeerPtr]
    pub fn peer(&self) -> PeerPtr {
        PeerPtr(self.0)
    }

    /// Immutable access to the value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this KnownInitConfResponsePtr does not exist.
    pub fn get<'a>(&self, srv: &'a CryptoServer) -> Option<&'a KnownInitConfResponse> {
        self.peer().get(srv).known_init_conf_response.as_ref()
    }

    /// Mutable access to the value
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced by this KnownInitConfResponsePtr does not exist.
    pub fn get_mut<'a>(&self, srv: &'a mut CryptoServer) -> Option<&'a mut KnownInitConfResponse> {
        self.peer().get_mut(srv).known_init_conf_response.as_mut()
    }

    /// Remove the cached response for this peer
    ///
    /// Takes care of updating the indices in [CryptoServer::index] appropriately.
    ///
    /// # Panic & Safety
    ///
    /// The function panics if
    ///
    /// - the peer referenced by this KnownInitConfResponsePtr does not exist
    /// - the peer contains a KnownInitConfResponse (i.e. if [Peer::known_init_conf_response] is Some(...)), but the index to this KnownInitConfResponsePtr is missing (i.e. there is no appropriate index
    ///   value in [CryptoServer::index])
    pub fn remove(&self, srv: &mut CryptoServer) -> Option<KnownInitConfResponse> {
        let peer = self.peer();
        let val = peer.get_mut(srv).known_init_conf_response.take()?;
        let lookup_key = PeerIndexKey::KnownInitConfResponse(val.request_mac);
        srv.index.remove(&lookup_key).unwrap();
        Some(val)
    }

    /// Insert a cached response for this peer
    ///
    /// Takes care of updating the indices in [CryptoServer::index] appropriately.
    ///
    /// # Panic & Safety
    ///
    /// The function panics if
    ///
    /// - the peer referenced by this KnownInitConfResponsePtr does not exist
    /// - the peer contains a KnownInitConfResponse (i.e. if [Peer::known_init_conf_response] is Some(...)), but the index to this KnownInitConfResponsePtr is missing (i.e. there is no appropriate index
    ///   value in [CryptoServer::index])
    pub fn insert(&self, srv: &mut CryptoServer, known_response: KnownInitConfResponse) {
        self.remove(srv).discard_result();

        let index_key = PeerIndexKey::KnownInitConfResponse(known_response.request_mac);
        self.peer().get_mut(srv).known_init_conf_response = Some(known_response);

        // There is a question here whether we should just discard the result…or panic if the
        // result is Some(...).
        //
        // The result being anything other than None should never occur:
        // - If we have never seen this InitConf message, then the result should be None and no value should
        //   have been written. This is fine.
        // - If we have seen this message before, we should have responded with a known answer –
        //   which would be fine
        // - If we have never seen this InitConf message before, but the hashes are the same, this
        //   would constitute a collision on our hash function, which is security because the
        //   cryptography (collision resistance of our hash) prevents this. If this happened, it
        //   would be bad but we could not detect it.
        if srv.index.insert(index_key, self.0).is_some() {
            log::warn!(
                r#"
                Replaced a cached message in the InitConf known-response table
                for network retransmission handling. This should never happen and is
                probably a bug. Please report seeing this message at the following location:
                
                https://github.com/rosenpass/rosenpass/issues
            "#
            );
        }
    }

    /// Look up the right [Self] for a given request message
    ///
    /// Really just calls [Self::index_key_for_msg] to produce the right
    /// index key followed by a lookup in [CryptoServer::index].
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced in the index does not exist.
    pub fn lookup_for_request_msg(
        srv: &CryptoServer,
        req: &Envelope<InitConf>,
    ) -> Option<KnownInitConfResponsePtr> {
        let index_key = Self::index_key_for_msg(srv, req);
        let peer_no = *srv.index.get(&index_key)?;
        Some(Self(peer_no))
    }

    /// Look up a cached response for a given request message
    ///
    /// Really just calls [Self::lookup_for_request_msg] followed [Self::get]
    /// and extracting [KnownResponse::response].
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced in the index does not exist.
    pub fn lookup_response_for_request_msg<'a>(
        srv: &'a CryptoServer,
        req: &Envelope<InitConf>,
    ) -> Option<&'a Envelope<EmptyData>> {
        Self::lookup_for_request_msg(srv, req)?
            .get(srv)
            .map(|v| &v.response)
    }

    /// Insert a cached response `res` for message `req` into [Peer::known_init_conf_response]
    /// for the peer referenced to by [PeerPtr] `peer`.
    ///
    /// 1. Creates an index key for `req` using [Self::index_key_hash_for_msg]
    /// 2. Constructs an appropriate [KnownInitConfResponse]
    /// 3. Uses [Self::insert] to insert the message and update the indices
    ///
    /// # Panic & Safety
    ///
    /// The function panics if the peer referenced to by `peer` does not exist.
    pub fn insert_for_request_msg(
        srv: &mut CryptoServer,
        peer: PeerPtr,
        req: &Envelope<InitConf>,
        res: Envelope<EmptyData>,
    ) {
        let ptr = peer.known_init_conf_response();
        ptr.insert(
            srv,
            KnownInitConfResponse {
                received_at: srv.timebase.now(),
                request_mac: Self::index_key_hash_for_msg(srv, req),
                response: res,
            },
        );
    }

    /// Calculate an appropriate index key hash for `req`
    ///
    /// Merely forwards [KnownResponseHasher::hash] with hasher [CryptoServer::known_response_hasher] from `srv`.
    pub fn index_key_hash_for_msg(
        srv: &CryptoServer,
        req: &Envelope<InitConf>,
    ) -> KnownResponseHash {
        srv.known_response_hasher.hash(req)
    }

    /// Calculate an appropriate index key for `req`
    ///
    /// Merely forwards [Self::index_key_for_msg] and wraps the result in [PeerIndexKey::KnownInitConfResponse]
    pub fn index_key_for_msg(srv: &CryptoServer, req: &Envelope<InitConf>) -> PeerIndexKey {
        Self::index_key_hash_for_msg(srv, req).apply(PeerIndexKey::KnownInitConfResponse)
    }
}

// DATABASE //////////////////////////////////////

impl CryptoServer {
    /// Constructing a CryptoServer
    ///
    /// # Examples
    ///
    /// ```
    /// use std::ops::DerefMut;
    /// use rosenpass::protocol::basic_types::{SSk, SPk};
    /// use rosenpass::protocol::{CryptoServer, ProtocolVersion};
    /// use rosenpass_ciphers::StaticKem;
    /// use rosenpass_cipher_traits::primitives::Kem;
    ///
    /// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    ///
    /// let (mut sskm, mut spkm) = (SSk::zero(), SPk::zero());
    /// StaticKem.keygen(sskm.secret_mut(), spkm.deref_mut())?;
    ///
    /// let srv = CryptoServer::new(sskm, spkm.clone());
    /// assert_eq!(srv.spkm, spkm);
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
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
            known_response_hasher: KnownResponseHasher::new(),
            peer_poll_off: 0,
            cookie_secrets: [CookieStore::new(), CookieStore::new()],
        }
    }

    /// Iterate over the available biscuit keys by their pointers [BiscuitKeyPtr]
    pub fn biscuit_key_ptrs(&self) -> impl Iterator<Item = BiscuitKeyPtr> {
        (0..self.biscuit_keys.len()).map(BiscuitKeyPtr)
    }

    /// Iterate over the available cookie secrets by their pointers [ServerCookieSecretPtr]
    pub fn cookie_secret_ptrs(&self) -> impl Iterator<Item = ServerCookieSecretPtr> {
        (0..self.cookie_secrets.len()).map(ServerCookieSecretPtr)
    }

    /// Calculate the peer ID of this CryptoServer
    #[rustfmt::skip]
    pub fn pidm(&self, keyed_hash: KeyedHash) -> Result<PeerId> {
        Ok(Public::new(
            hash_domains::peerid(keyed_hash)?
                .mix(self.spkm.deref())?
                .into_value()))
    }

    /// Iterate over all peers, starting with the `n`th peer, wrapping at the
    /// end of the peers vec so that also all peers from index 0 to `n - 1` are
    /// yielded
    pub fn peer_ptrs_off(&self, n: usize) -> impl Iterator<Item = PeerPtr> {
        let l = self.peers.len();
        (0..l).map(move |i| PeerPtr((i + n) % l))
    }

    /// Add a peer with an optional pre shared key (`psk`), its public key (`pk`) and the peer's
    /// protocol version (`protocol_version`).
    ///
    /// ```
    /// use std::ops::DerefMut;
    /// use rosenpass::protocol::basic_types::{SSk, SPk, SymKey};
    /// use rosenpass::protocol::osk_domain_separator::OskDomainSeparator;
    /// use rosenpass::protocol::{CryptoServer, ProtocolVersion};
    /// use rosenpass_ciphers::StaticKem;
    /// use rosenpass_cipher_traits::primitives::Kem;
    ///
    /// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    ///
    /// let (mut sskm, mut spkm) = (SSk::zero(), SPk::zero());
    /// StaticKem.keygen(sskm.secret_mut(), spkm.deref_mut())?;
    /// let mut srv = CryptoServer::new(sskm, spkm);
    ///
    /// let (mut sskt, mut spkt) = (SSk::zero(), SPk::zero());
    /// StaticKem.keygen(sskt.secret_mut(), spkt.deref_mut())?;
    ///
    /// let psk = SymKey::random();
    /// // We use the latest protocol version for the example.
    /// let peer = srv.add_peer(Some(psk), spkt.clone(), ProtocolVersion::V03, OskDomainSeparator::for_wireguard_psk())?;
    ///
    /// assert_eq!(peer.get(&srv).spkt, spkt);
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    pub fn add_peer(
        &mut self,
        psk: Option<SymKey>,
        pk: SPk,
        protocol_version: ProtocolVersion,
        osk_domain_separator: OskDomainSeparator,
    ) -> Result<PeerPtr> {
        let peer = Peer {
            psk: psk.unwrap_or_else(SymKey::zero),
            spkt: pk,
            biscuit_used: BiscuitId::zero(),
            session: None,
            handshake: None,
            known_init_conf_response: None,
            initiation_requested: false,
            protocol_version,
            osk_domain_separator,
        };
        let peerid = peer.pidt()?;
        let peerno = self.peers.len();
        match self.index.entry(PeerIndexKey::Peer(peerid)) {
            Occupied(_) => bail!(
                "Cannot insert peer with id {:?}; peer with this id already registered.",
                peerid
            ),
            Vacant(e) => e.insert(peerno),
        };
        self.peers.push(peer);
        Ok(PeerPtr(peerno))
    }

    /// Register a new session
    ///
    /// Used in [SessionPtr::insert] and [IniHsPtr::insert].
    ///
    /// The function will raise an error if the given session ID is already used for a different
    /// peer; if the session ID is already registered for the given peer, then the index is left
    /// unchanged.
    ///
    /// The session id `id` must be chosen by the local peer; it is a "sidm" (Session ID Mine).
    ///
    /// To rgister a session, you should generally use [SessionPtr::insert] or [IniHsPtr::insert]
    /// instead of this, more lower level function.
    pub fn register_session(&mut self, id: SessionId, peer: PeerPtr) -> Result<()> {
        match self.index.entry(PeerIndexKey::Sid(id)) {
            Occupied(p) if PeerPtr(*p.get()) == peer => {} // Already registered
            Occupied(_) => bail!("Cannot insert session with id {:?}; id is in use.", id),
            Vacant(e) => {
                e.insert(peer.0);
            }
        };
        Ok(())
    }

    /// Unregister a session previously registered using [Self::register_session]
    ///
    /// If the session is not registered, the index is left unchanged.
    ///
    /// This is generally used only in the context of [Self::unregister_session_if_vacant].
    ///
    /// To unregister a session, you should generally use [SessionPtr::take] or [IniHsPtr::take]
    /// instead of this, more lower level function.
    pub fn unregister_session(&mut self, id: SessionId) {
        self.index.remove(&PeerIndexKey::Sid(id));
    }

    /// Unregister a session previously registered using [Self::register_session],
    /// if and only if the associated sessions are no longer present in their peer.
    ///
    /// This means that the peer's [Peer::session] and [Peer::handshake] fields must
    /// be cleared if they refer to this session before calling this function.
    ///
    /// In particular, this function checks:
    ///
    /// - For handshakes: [Peer::handshake] -> [InitiatorHandshake::core] -> [HandshakeState::sidi]
    /// - For sessions: [Peer::session] -> [Session::sidm]
    ///
    /// To unregister a session, you should generally use [SessionPtr::take] or [IniHsPtr::take]
    /// instead of this, more lower level function.
    pub fn unregister_session_if_vacant(&mut self, id: SessionId, peer: PeerPtr) {
        match (peer.session().get(self), peer.hs().get(self)) {
            (Some(ses), _) if ses.sidm == id => {}    /* nop */
            (_, Some(hs)) if hs.core.sidi == id => {} /* nop */
            _ => self.unregister_session(id),
        };
    }

    /// Find a peer given its peer ID as produced by [Peer::pidt]
    ///
    /// This function is used in cryptographic message processing
    /// [CryptoServer::handle_init_hello], and [HandshakeState::load_biscuit]
    pub fn find_peer(&self, id: PeerId) -> Option<PeerPtr> {
        self.index
            .get(&PeerIndexKey::Peer(id))
            .map(|no| PeerPtr(*no))
    }

    /// Look up a handshake given its session id [HandshakeState::sidi]
    ///
    /// This is called `lookup_session` in [whitepaper](https://rosenpass.eu/whitepaper.pdf).
    pub fn lookup_handshake(&self, id: SessionId) -> Option<IniHsPtr> {
        self.index
            .get(&PeerIndexKey::Sid(id)) // lookup the session in the index
            .map(|no| IniHsPtr(*no)) // convert to peer pointer
            .filter(|hsptr| {
                hsptr
                    .get(self) // lookup in the server
                    .as_ref()
                    .map(|hs| hs.core.sidi == id) // check that handshake id matches as well
                    .unwrap_or(false) // it didn't match?!
            })
    }

    /// Look up a session given its session id [Session::sidm]
    ///
    /// This is called `lookup_session` in [whitepaper](https://rosenpass.eu/whitepaper.pdf).
    pub fn lookup_session(&self, id: SessionId) -> Option<SessionPtr> {
        self.index
            .get(&PeerIndexKey::Sid(id))
            .map(|no| SessionPtr(*no))
            .filter(|sptr| {
                sptr.get(self)
                    .as_ref()
                    .map(|ses| ses.sidm == id)
                    .unwrap_or(false)
            })
    }

    /// Retrieve the active biscuit key, cycling biscuit keys if necessary.
    ///
    /// Two biscuit keys are maintained inside [Self::biscuit_keys]; they are
    /// considered fresh ([Lifecycle::Young]) for one [BISCUIT_EPOCH] after creation,
    /// and they are considered stale ([Lifecycle::Retired]) for another [BISCUIT_EPOCH].
    ///
    /// While young, they are used for encryption of biscuits and while retired they are
    /// just use for decryption. Keeping stale biscuits keys around makes sure that
    /// no handshakes are dropped when biscuit keys are changed.
    ///
    /// This function will return the newest fresh biscuit; if there are no fresh biscuits,
    /// the oldest biscuit will be replaced with a fresh one using [CookieStore::randomize].
    ///
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

    /// Return all fresh ([Lifecycle::Young]) or stale ([Lifecycle::Retired])
    /// cookie secrets (from [Self::cookie_secrets]) ordered by age, youngest ones
    /// first.
    ///
    /// If none of the cookie secrets are fresh or stale, the oldest cookie secret will
    /// be refreshed using [CookieSecret::randomize]; this function therefor always returns
    /// at least one usable, fresh cookie secret.
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
    /// Create a new peer from the peers keys.
    ///
    /// If no peer PSK is set, `psk` should be initialized to [SymKey::zero].
    ///
    /// # Examples
    ///
    /// See example in [Self].
    pub fn new(
        psk: SymKey,
        pk: SPk,
        protocol_version: ProtocolVersion,
        osk_domain_separator: OskDomainSeparator,
    ) -> Peer {
        Peer {
            psk,
            spkt: pk,
            biscuit_used: BiscuitId::zero(),
            session: None,
            handshake: None,
            known_init_conf_response: None,
            initiation_requested: false,
            protocol_version,
            osk_domain_separator,
        }
    }

    /// Compute the peer ID of the peer,
    /// as specified in the [whitepaper](https://rosenpass.eu/whitepaper.pdf).
    ///
    /// # Examples
    ///
    /// See example in [Self].
    #[rustfmt::skip]
    pub fn pidt(&self) -> Result<PeerId> {
        Ok(Public::new(
            hash_domains::peerid(self.protocol_version.keyed_hash())?
                .mix(self.spkt.deref())?
                .into_value()))
    }
}

impl Session {
    /// Zero initialization of a session
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{Session, HandshakeRole};
    /// use rosenpass_ciphers::KeyedHash;
    ///
    /// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
    ///
    /// let s = Session::zero(KeyedHash::keyed_shake256());
    /// assert_eq!(s.created_at, 0.0);
    /// assert_eq!(s.handshake_role, HandshakeRole::Initiator);
    /// ```
    pub fn zero(keyed_hash: KeyedHash) -> Self {
        Self {
            created_at: 0.0,
            sidm: SessionId::zero(),
            sidt: SessionId::zero(),
            handshake_role: HandshakeRole::Initiator,
            ck: SecretHashDomain::zero(keyed_hash).dup(),
            txkm: SymKey::zero(),
            txkt: SymKey::zero(),
            txnm: 0,
            txnt: 0,
        }
    }
}

// COOKIE STORE ///////////////////////////////////
impl<const N: usize> CookieStore<N> {
    /// Creates a new cookie store value with a random secret value
    /// and a [Self::created_at] value of [BCE].
    ///
    /// # Examples
    ///
    /// See [Self].
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            created_at: BCE,
            value: Secret::<N>::random(),
        }
    }

    /// Resets [Self] by randomizing [Self::value] and setting
    /// [Self::created_at] to [BCE].
    ///
    /// # Examples
    ///
    /// See [Self].
    pub fn erase(&mut self) {
        self.value.randomize();
        self.created_at = BCE;
    }

    /// Refresh the cookie store with a random secret.
    ///
    /// [Self::value] will be a random key and [Self::created_at]
    /// will be set to the current time.
    ///
    /// `tb`, the Timebase is the reference point for time keeping.
    /// Usually this should be [CryptoServer::timebase].
    ///
    /// # Examples
    ///
    /// See [Self].
    pub fn randomize(&mut self, tb: &Timebase) {
        self.value.randomize();
        self.created_at = tb.now();
    }

    /// Refresh the cookie store with a random secret.
    ///
    /// [Self::value] will be set to and [Self::created_at]
    /// will be set to the current time.
    ///
    /// `tb`, the Timebase is the reference point for time keeping.
    /// Usually this should be [CryptoServer::timebase].
    ///
    /// # Examples
    ///
    /// See [Self].
    pub fn update(&mut self, tb: &Timebase, value: &[u8]) {
        self.value.secret_mut().copy_from_slice(value);
        self.created_at = tb.now();
    }
}

// LIFECYCLE MANAGEMENT //////////////////////////

impl Mortal for IniHsPtr {
    /// At [InitiatorHandshake::created_at]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.get(srv).as_ref().map(|hs| hs.created_at)
    }

    /// No retirement phase; same as [Self::die_at]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.die_at(srv)
    }

    /// [Self::created_at] plus [REJECT_AFTER_TIME]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + REJECT_AFTER_TIME)
    }
}

impl Mortal for SessionPtr {
    /// At [Session::created_at]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.get(srv).as_ref().map(|p| p.created_at)
    }

    /// [Self::created_at] plus [REKEY_AFTER_TIME_INITIATOR] or [REKEY_AFTER_TIME_RESPONDER]
    /// as appropriate.
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

    /// [Self::created_at] plus [REJECT_AFTER_TIME]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + REJECT_AFTER_TIME)
    }
}

impl Mortal for BiscuitKeyPtr {
    /// At [BiscuitKey::created_at]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        let t = self.get(srv).created_at;
        if t < 0.0 {
            None
        } else {
            Some(t)
        }
    }

    /// At [Self::created_at] plus [BISCUIT_EPOCH]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + BISCUIT_EPOCH)
    }

    /// At [Self::retire_at] plus [BISCUIT_EPOCH]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.retire_at(srv).map(|t| t + BISCUIT_EPOCH)
    }
}

impl Mortal for ServerCookieSecretPtr {
    /// At [CookieSecret::created_at]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        let t = self.get(srv).created_at;
        if t < 0.0 {
            None
        } else {
            Some(t)
        }
    }

    /// At [Self::created_at] plus [COOKIE_SECRET_EPOCH]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + COOKIE_SECRET_EPOCH)
    }

    /// At [Self::retire_at] plus [COOKIE_SECRET_EPOCH]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.retire_at(srv).map(|t| t + COOKIE_SECRET_EPOCH)
    }
}

impl Mortal for PeerCookieValuePtr {
    /// At [CookieStore::created_at]
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

    /// No retirement phase, so this is the same as [Self::die_at]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.die_at(srv)
    }

    /// [Self::created_at] plus [PEER_COOKIE_VALUE_EPOCH]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + PEER_COOKIE_VALUE_EPOCH)
    }
}

impl Mortal for KnownInitConfResponsePtr {
    /// At [KnownInitConfResponse::received_at]
    fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
        let t = self.get(srv)?.received_at;
        if t < 0.0 {
            None
        } else {
            Some(t)
        }
    }

    /// No retirement phase, so this is the same as [Self::die_at]
    fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.die_at(srv)
    }

    /// [Self::created_at] plus [REKEY_AFTER_TIME_RESPONDER]
    fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
        self.created_at(srv).map(|t| t + REKEY_AFTER_TIME_RESPONDER)
    }
}

/// Trait extension to the [Mortal] Trait, that enables nicer access to timing
/// information
///
/// # Examples
///
/// ```
/// use rosenpass::protocol::{timing::Timing, Mortal, MortalExt, Lifecycle, CryptoServer, ProtocolVersion};
/// use rosenpass::protocol::testutils::{ServerForTesting, time_travel_forward};
///
/// rosenpass_secret_memory::secret_policy_try_use_memfd_secrets();
///
/// const M : Timing = 60.0;
/// const H : Timing = 60.0 * M;
/// const D : Timing = 24.0 * H;
/// const Y : Timing = 356.0 * D;
///
/// let mut ts = ServerForTesting::new(ProtocolVersion::V03)?;
///
/// fn eq_up_to_minute(a: Timing, b: Timing) -> bool {
///   (a - b) < M
/// }
///
/// struct Hooman {
///   born: Timing,
///   works_for: Timing,
///   retires_for: Timing,
/// };
///
/// impl Mortal for Hooman {
///     fn created_at(&self, srv: &CryptoServer) -> Option<Timing> {
///         Some(self.born)
///     }
///    
///     fn retire_at(&self, srv: &CryptoServer) -> Option<Timing> {
///         Some(self.created_at(&srv)? + self.works_for)
///     }
///    
///     fn die_at(&self, srv: &CryptoServer) -> Option<Timing> {
///         Some(self.retire_at(&srv)? + self.retires_for)
///     }
/// }
///
/// let twist = Hooman {
///     born: ts.srv.timebase.now(),
///     works_for: 79.0 * Y, // Post-capitalist feudal state
///     retires_for: 4.0 * M,
/// };
///
/// assert!(eq_up_to_minute(twist.life_left(&ts.srv).unwrap(), twist.works_for + twist.retires_for));
/// assert!(eq_up_to_minute(twist.youth_left(&ts.srv).unwrap(), twist.works_for));
/// assert_eq!(twist.lifecycle(&ts.srv), Lifecycle::Young);
///
/// // Travel forward by 4Y
/// time_travel_forward(&mut ts.srv, 4.0*Y);
/// assert!(eq_up_to_minute(twist.life_left(&ts.srv).unwrap(), twist.works_for + twist.retires_for - 4.0*Y));
/// assert!(eq_up_to_minute(twist.youth_left(&ts.srv).unwrap(), twist.works_for - 4.0*Y));
/// assert_eq!(twist.lifecycle(&ts.srv), Lifecycle::Young);
///
/// // Travel forward past their retirement
/// let dst = twist.youth_left(&ts.srv).unwrap() + 1.0*M;
/// time_travel_forward(&mut ts.srv, dst);
/// assert!(eq_up_to_minute(twist.life_left(&ts.srv).unwrap(), 3.0*M));
/// assert!(eq_up_to_minute(twist.youth_left(&ts.srv).unwrap(), -1.0*M));
/// assert_eq!(twist.lifecycle(&ts.srv), Lifecycle::Retired);
///
/// // Travel forward past their death
/// let dst = twist.life_left(&ts.srv).unwrap() + 1.0*Y;
/// time_travel_forward(&mut ts.srv, dst);
/// assert!(eq_up_to_minute(twist.life_left(&ts.srv).unwrap(), -1.0*Y));
/// assert!(eq_up_to_minute(twist.youth_left(&ts.srv).unwrap(), -1.0*Y + 4.0*M));
/// assert_eq!(twist.lifecycle(&ts.srv), Lifecycle::Dead);
///
/// Ok::<(), anyhow::Error>(())
/// ```
pub trait MortalExt: Mortal {
    /// Calculate the amount of time left before the object enters
    /// lifecycle stage [Lifecycle::Dead].
    ///
    /// # Examples
    ///
    /// See [Self].
    fn life_left(&self, srv: &CryptoServer) -> Option<Timing>;
    /// Calculate the amount of time left before the object enters
    /// lifecycle stage [Lifecycle::Retired].
    ///
    /// # Examples
    ///
    /// See [Self].
    fn youth_left(&self, srv: &CryptoServer) -> Option<Timing>;
    /// Retrieve the current [Lifecycle] stage
    ///
    /// # Examples
    ///
    /// See [Self].
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
    /// This is the function that a user of [Self] should use to start a new handshake.
    ///
    /// The generated message is put into the `tx_buf` parameter and the size of the message
    /// is returned by the function. The buffer must be large enough to store a value of
    /// [Envelope]<[InitHello]>. Usually, the same buffer would be used for all messages;
    /// in this case allocating the message buffer with [MsgBuf] is easiest.
    ///
    /// If there already is an ongoing handshake in initiator role
    /// for the given peer, this function will displace this other handshake,
    /// causing any further packages that are part of the other handshake to be
    /// rejected by [Self::handle_msg].
    ///
    /// This can be called at any time, but most users may wish to call this function
    /// after [Self::poll] returns [PollResult::SendInitiation]. Note that ignoring
    /// [PollResult::SendInitiation] is explicitly supported. The Rosenpass application
    /// does this for instance when there is no known address for the other peer.
    ///
    /// # Panic & Safety
    ///
    /// Will panic if the given buffer `tx_buf` is not large enough.
    ///
    /// # Example
    ///
    /// See the example on how to use this function without [Self::poll] in [crate::protocol].
    ///
    /// See [Self::poll] on how to use this function with poll.
    pub fn initiate_handshake(&mut self, peer: PeerPtr, tx_buf: &mut [u8]) -> Result<usize> {
        // NOTE retransmission? yes if initiator, no if responder
        // TODO remove unnecessary copying between global tx_buf and per-peer buf
        // TODO move retransmission storage to io server
        //
        // Envelope::<InitHello>::default(); // TODO
        let mut msg = truncating_cast_into::<Envelope<InitHello>>(tx_buf)?;
        self.handle_initiation(peer, &mut msg.payload)?;
        let len = self.seal_and_commit_msg(peer, MsgType::InitHello, &mut msg)?;
        peer.hs()
            .store_msg_for_retransmission(self, msg.as_bytes())?;
        Ok(len)
    }
}

/// The type returned by [CryptoServer::handle_msg]
#[derive(Debug)]
pub struct HandleMsgResult {
    /// If a key was successfully exchanged with another party as a result of
    /// this network message, then this field indicates which peer.
    ///
    /// The key can then be accessed through the session; see [PeerPtr::session].
    pub exchanged_with: Option<PeerPtr>,
    /// If processing the message yielded a response, then this field indicates its size.
    ///
    /// The message data will be in a buffer given to function as a mutable parameter.
    ///
    /// This message should be sent to the other party on the channel that they used to send
    /// the request. Note that, even if there is some known IP address for the peer, this address
    /// should generally not be used as this would preclude IP switching.
    pub resp: Option<usize>,
}

/// Produces identifying information about the sender of a network package.
///
/// Used in [CryptoServer::handle_msg_under_load] to perform proof-of-address-ownership
/// with the other party.
///
/// The result is quite deliberately a byte slice, this allows users of [CryptoServer]
/// to provide support for arbitrary types of addresses.
pub trait HostIdentification: Display {
    /// Byte slice representing the host identification
    fn encode(&self) -> &[u8];
}

impl CryptoServer {
    /// Process a message under load.
    ///
    /// This is one of the main entry points for the protocol. The function can be used
    /// as a substitute for [CryptoServer::handle_msg] when the user of [CryptoServer]
    /// has determined that a DOS attack is being performed.
    ///
    /// Keeps track of messages processed, and qualifies messages using
    /// cookie based DoS mitigation.
    ///
    /// If receiving a InitHello message, it dispatches message for further processing
    /// to `process_msg` handler if cookie is valid otherwise sends a cookie reply
    /// message for sender to process and verify for messages part of the handshake phase
    ///
    /// Directly processes InitConf messages.
    ///
    /// Bails on messages sent by responder and non-handshake messages.
    ///
    /// # Examples
    ///
    /// Using this function is a bit complex and the toughest part is how to perform DOS
    /// mitigation.
    ///
    /// The best places to check out to learn more about how this function can be used
    /// are the tests:
    ///
    /// - test::cookie_reply_mechanism_responder_under_load
    /// - test::cookie_reply_mechanism_initiator_bails_on_message_under_load
    #[cfg(not(feature = "experiment_cookie_dos_mitigation"))]
    #[inline]
    pub fn handle_msg_under_load<H: HostIdentification>(
        &mut self,
        rx_buf: &[u8],
        tx_buf: &mut [u8],
        host_identification: &H,
    ) -> Result<HandleMsgResult> {
        self.handle_msg(rx_buf, tx_buf)
    }

    #[cfg(feature = "experiment_cookie_dos_mitigation")]
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
                    &hash_domains::cookie_value(KeyedHash::keyed_shake256())?
                        .mix(cookie_secret)?
                        .mix(host_identification.encode())?
                        .into_value()[..16],
                );

                // Most recently filled value is active cookie value
                if active_cookie_value.is_none() {
                    active_cookie_value = Some(cookie_value);
                }

                let mut expected = [0u8; COOKIE_SIZE];

                let msg_in = Ref::<&[u8], Envelope<InitHello>>::new(rx_buf)
                    .ok_or(RosenpassError::BufferSizeMismatch)?;
                expected.copy_from_slice(
                    &hash_domains::cookie(KeyedHash::keyed_shake256())?
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

        // Otherwise send cookie reply
        if active_cookie_value.is_none() {
            bail!("No active cookie value found");
        }

        log::debug!(
            "Rx {:?} from {} under load, tx cookie reply message",
            msg_type,
            host_identification
        );

        let cookie_value = active_cookie_value.unwrap();
        let cookie_key = hash_domains::cookie_key(KeyedHash::keyed_shake256())?
            .mix(self.spkm.deref())?
            .into_value();

        let mut msg_out = truncating_cast_into::<CookieReply>(tx_buf)?;

        let nonce = XAEADNonce::random();

        msg_out.inner.msg_type = MsgType::CookieReply.into();
        msg_out.inner.sid = rx_sid;

        XAead.encrypt_with_nonce_in_ctxt(
            &mut msg_out.inner.cookie_encrypted[..],
            &cookie_key,
            &nonce.value,
            &rx_mac,
            &cookie_value,
        )?;

        {
            use rand::Fill;
            msg_out
                .padding
                .try_fill(&mut rosenpass_secret_memory::rand::rng())
                .unwrap();
        }

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
    ///
    /// # Examples
    ///
    /// See the example on how to use this function without [Self::poll] in [crate::protocol].
    ///
    /// See [Self::poll] on how to use this function with poll.
    pub fn handle_msg(&mut self, rx_buf: &[u8], tx_buf: &mut [u8]) -> Result<HandleMsgResult> {
        let seal_broken = "Message seal broken!";
        // length of the response. We assume no response, so None for now
        let mut len = 0;
        let mut exchanged = false;

        ensure!(!rx_buf.is_empty(), "received empty message, ignoring it");

        let msg_type = rx_buf[0].try_into();

        log::debug!("Rx {:?}, processing", msg_type);

        let mut msg_out = truncating_cast_into::<Envelope<RespHello>>(tx_buf)?;

        let peer = match msg_type {
            Ok(MsgType::InitHello) => {
                let msg_in: Ref<&[u8], Envelope<InitHello>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;

                // At this point, we do not know the hash functon used by the peer, thus we try both,
                // with a preference for SHAKE256.
                let peer_shake256 = self.handle_init_hello(
                    &msg_in.payload,
                    &mut msg_out.payload,
                    KeyedHash::keyed_shake256(),
                );
                let (peer, peer_hash_choice) = match peer_shake256 {
                    Ok(peer) => (peer, KeyedHash::keyed_shake256()),
                    Err(_) => {
                        let peer_blake2b = self.handle_init_hello(
                            &msg_in.payload,
                            &mut msg_out.payload,
                            KeyedHash::incorrect_hmac_blake2b(),
                        );
                        match peer_blake2b {
                            Ok(peer) => (peer, KeyedHash::incorrect_hmac_blake2b()),
                            Err(_) => bail!("No valid hash function found for InitHello"),
                        }
                    }
                };
                // Now, we make sure that the hash function used by the peer is the same as the one
                // that is specified in the local configuration.
                self.verify_hash_choice_match(peer, peer_hash_choice.clone())?;

                ensure!(msg_in.check_seal(self, peer_hash_choice)?, seal_broken);

                len = self.seal_and_commit_msg(peer, MsgType::RespHello, &mut msg_out)?;
                peer
            }
            Ok(MsgType::RespHello) => {
                let msg_in: Ref<&[u8], Envelope<RespHello>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;

                let mut msg_out = truncating_cast_into::<Envelope<InitConf>>(tx_buf)?;
                let peer = self.handle_resp_hello(&msg_in.payload, &mut msg_out.payload)?;
                ensure!(
                    msg_in.check_seal(self, peer.get(self).protocol_version.keyed_hash())?,
                    seal_broken
                );

                len = self.seal_and_commit_msg(peer, MsgType::InitConf, &mut msg_out)?;
                peer.hs()
                    .store_msg_for_retransmission(self, &msg_out.as_bytes()[..len])?;
                exchanged = true;
                peer
            }
            Ok(MsgType::InitConf) => {
                let msg_in: Ref<&[u8], Envelope<InitConf>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;

                let mut msg_out = truncating_cast_into::<Envelope<EmptyData>>(tx_buf)?;

                // Check if we have a cached response
                let peer = match KnownInitConfResponsePtr::lookup_for_request_msg(self, &msg_in) {
                    // Cached response; copy out of cache
                    Some(cached) => {
                        let peer = cached.peer();
                        ensure!(
                            msg_in
                                .check_seal(self, peer.get(self).protocol_version.keyed_hash())?,
                            seal_broken
                        );
                        let cached = cached
                            .get(self)
                            .map(|v| v.response.borrow())
                            // Invalid! Found peer no with cache in index but the cache does not exist
                            .unwrap();
                        copy_slice(cached.as_bytes()).to(msg_out.as_bytes_mut());
                        peer
                    }

                    // No cached response, actually call cryptographic handler
                    None => {
                        // At this point, we do not know the hash functon used by the peer, thus we try both,
                        // with a preference for SHAKE256.
                        let peer_shake256 = self.handle_init_conf(
                            &msg_in.payload,
                            &mut msg_out.payload,
                            KeyedHash::keyed_shake256(),
                        );
                        let (peer, peer_hash_choice) = match peer_shake256 {
                            Ok(peer) => (peer, KeyedHash::keyed_shake256()),
                            Err(_) => {
                                let peer_blake2b = self.handle_init_conf(
                                    &msg_in.payload,
                                    &mut msg_out.payload,
                                    KeyedHash::incorrect_hmac_blake2b(),
                                );
                                match peer_blake2b {
                                    Ok(peer) => (peer, KeyedHash::incorrect_hmac_blake2b()),
                                    Err(_) => bail!("No valid hash function found for InitHello"),
                                }
                            }
                        };
                        // Now, we make sure that the hash function used by the peer is the same as the one
                        // that is specified in the local configuration.
                        self.verify_hash_choice_match(peer, peer_hash_choice.clone())?;
                        ensure!(msg_in.check_seal(self, peer_hash_choice)?, seal_broken);

                        KnownInitConfResponsePtr::insert_for_request_msg(
                            self,
                            peer,
                            &msg_in,
                            msg_out.clone(),
                        );

                        exchanged = true;
                        peer
                    }
                };

                len = self.seal_and_commit_msg(peer, MsgType::EmptyData, &mut msg_out)?;
                peer
            }
            Ok(MsgType::EmptyData) => {
                let msg_in: Ref<&[u8], Envelope<EmptyData>> =
                    Ref::new(rx_buf).ok_or(RosenpassError::BufferSizeMismatch)?;

                self.handle_resp_conf(&msg_in, seal_broken.to_string())?
            }
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

    /// Given a peer and a [KeyedHash] `peer_hash_choice`, this function checks whether the
    /// `peer_hash_choice` matches the hash function that is expected for the peer.
    fn verify_hash_choice_match(&self, peer: PeerPtr, peer_hash_choice: KeyedHash) -> Result<()> {
        match peer.get(self).protocol_version.keyed_hash() {
            KeyedHash::KeyedShake256(_) => match peer_hash_choice {
                KeyedHash::KeyedShake256(_) => Ok(()),
                KeyedHash::IncorrectHmacBlake2b(_) => bail!("Hash function mismatch"),
            },
            KeyedHash::IncorrectHmacBlake2b(_) => match peer_hash_choice {
                KeyedHash::KeyedShake256(_) => bail!("Hash function mismatch"),
                KeyedHash::IncorrectHmacBlake2b(_) => Ok(()),
            },
        }
    }

    /// This is used to finalize a message in a transmission buffer
    /// while ensuring that the [Envelope::mac] and [Envelope::cookie]
    /// fields are properly filled.
    ///
    /// The message type is explicitly required as a measure of defensive
    /// programming, because it is very easy to forget setting the message type,
    /// which creates subtle impactful.
    ///
    /// To save some code, the function returns the size of the message,
    /// but the same could be easily achieved by calling [size_of] with the
    /// message type or by calling [AsBytes::as_bytes] on the message reference.
    pub fn seal_and_commit_msg<M: AsBytes + FromBytes>(
        &mut self,
        peer: PeerPtr,
        msg_type: MsgType,
        msg: &mut Ref<&mut [u8], Envelope<M>>,
    ) -> Result<usize> {
        // TODO: This function is too unspecific and does not do a lot. We should inline it.
        msg.msg_type = msg_type as u8;
        msg.seal(peer, self)?;
        Ok(size_of::<Envelope<M>>())
    }
}

// EVENT POLLING /////////////////////////////////

/// Special, named type for representing waiting periods in the context
/// of producing a [PollResult]
#[derive(Debug, Copy, Clone)]
pub struct Wait(pub Timing);

impl Wait {
    /// Produce a zero-valued [Self], basically indicating that some [Pollable::poll]
    /// or [CryptoServer::poll] should be called again immediately.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::Wait;
    ///
    /// assert_eq!(Wait::immediate().0, 0.0);
    /// ```
    pub fn immediate() -> Self {
        Wait(0.0)
    }

    /// Produce a [Self] valued [UNENDING], basically indicating that
    /// no scheduled wakeup time could be determined
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{Wait, timing::UNENDING};
    ///
    /// assert_eq!(Wait::hibernate().0, UNENDING);
    /// ```
    pub fn hibernate() -> Self {
        Wait(UNENDING)
    }

    /// Equivalent to [Self::immediate] or [Self::hibernate], depending
    /// the given condition
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{Wait, timing::UNENDING};
    ///
    /// assert_eq!(Wait::immediate_unless(false).0, 0.0);
    /// assert_eq!(Wait::immediate_unless(true).0, UNENDING);
    /// ```
    pub fn immediate_unless(cond: bool) -> Self {
        if cond {
            Self::hibernate()
        } else {
            Self::immediate()
        }
    }

    /// Use the given timing value or hibernate if None
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{Wait, timing::UNENDING};
    ///
    /// assert_eq!(Wait::or_hibernate(None).0, UNENDING);
    /// assert_eq!(Wait::or_hibernate(Some(20.0)).0, 20.0);
    /// ```
    pub fn or_hibernate(t: Option<Timing>) -> Self {
        match t {
            Some(u) => Wait(u),
            None => Wait::hibernate(),
        }
    }

    /// Use the given timing value or [Self::immediate] if none
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{Wait, timing::UNENDING};
    ///
    /// assert_eq!(Wait::or_immediate(None).0, 0.0);
    /// assert_eq!(Wait::or_immediate(Some(20.0)).0, 20.0);
    /// ```
    pub fn or_immediate(t: Option<Timing>) -> Self {
        match t {
            Some(u) => Wait(u),
            None => Wait::immediate(),
        }
    }

    /// Wait for the longer of two possible times
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{Wait, timing::UNENDING};
    ///
    ///
    /// assert_eq!(Wait(20.0).and(30.0).0, 30.0);
    /// ```
    pub fn and<T: Into<Wait>>(&self, o: T) -> Self {
        let (a, b) = (self.0, o.into().0);
        Wait(if a > b { a } else { b })
    }
}

impl From<Timing> for Wait {
    /// Wraps [Timing] into [Self]
    fn from(t: Timing) -> Wait {
        Wait(t)
    }
}

impl From<Option<Timing>> for Wait {
    /// Equivalent to [Wait::or_hibernate]
    fn from(t: Option<Timing>) -> Wait {
        Wait::or_hibernate(t)
    }
}

/// Result of a poll operation [Pollable::poll] or [CryptoServer::poll],
/// instructing the caller on how to proceed
///
/// This type also contains a lot of handy functions for performing polling
/// in a nice style. The best place to see this in action is the source code
/// of [CryptoServer::poll].
#[derive(Debug, Copy, Clone)]
pub enum PollResult {
    /// The caller should wait for IO events until the indicated deadline.
    ///
    /// After the deadline, the caller should call poll again.
    ///
    /// If the IO operation produces events before the deadline, the IO messages
    /// should be processed – likely by using [CryptoServer::handle_msg] before
    /// immediately calling poll again.
    ///
    /// If the value is `Sleep(0.0)`, then the caller should immediately call
    /// poll again.
    Sleep(Timing),
    /// The caller should immediately erase any cryptographic keys exchanged with
    /// the peer previously and then immediately call poll again.
    ///
    /// This is raised after [REJECT_AFTER_TIME] if no successful rekey could be achieved.
    DeleteKey(PeerPtr),
    /// The caller should invoke [CryptoServer::handle_initiation] and transmit the
    /// initiation to the other party before invoking poll again.
    SendInitiation(PeerPtr),
    /// The caller should invoke [CryptoServer::retransmit_handshake] and transmit the
    /// resulting message to the other party before invoking poll again.
    SendRetransmission(PeerPtr),
}

impl Default for PollResult {
    /// Equal to [Self::hibernate]
    fn default() -> Self {
        Self::hibernate()
    }
}

impl PollResult {
    /// Produce a [Self::Sleep] valued [UNENDING], basically indicating that
    /// no scheduled wakeup time could be determined and that the caller
    /// should wait for IO operations indefinitely.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, timing::UNENDING};
    ///
    /// assert!(matches!(PollResult::hibernate(), PollResult::Sleep(UNENDING)));
    /// ```
    pub fn hibernate() -> Self {
        Self::Sleep(UNENDING) // Avoid excessive sleep times (might trigger bugs on some platforms)
    }

    /// Returns the peer this poll result refers to some peer; i.e. if this poll result is not
    /// [Self::Sleep]:
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, PeerPtr, timing::UNENDING};
    ///
    /// let p = PeerPtr(0);
    ///
    /// assert_eq!(PollResult::Sleep(0.0).peer(), None);
    /// assert_eq!(PollResult::DeleteKey(p).peer(), Some(p));
    /// assert_eq!(PollResult::SendInitiation(p).peer(), Some(p));
    /// assert_eq!(PollResult::SendRetransmission(p).peer(), Some(p));
    /// ```
    pub fn peer(&self) -> Option<PeerPtr> {
        use PollResult::*;
        match *self {
            DeleteKey(p) | SendInitiation(p) | SendRetransmission(p) => Some(p),
            _ => None,
        }
    }

    /// Select the higher-priority poll result from two poll results.
    ///
    /// - If both poll results are unsaturated (i.e. [Self::Sleep]), sleeps for
    ///   the shorter time
    /// - If one of the poll results is [PollResult::saturated], returns that one
    /// - If both results are saturated: Panics. If you need this functionality, see
    ///   [Self::try_fold_with].
    ///
    /// This is enormously useful when dealing with many objects that need polling.
    ///
    /// # Panic & Safety
    ///
    /// Panics if both poll results are [PollResult::saturated]
    ///
    /// ```should_panic
    /// use rosenpass::protocol::{PollResult, PeerPtr};
    ///
    /// let p = PeerPtr(0);
    ///
    /// use PollResult as P;
    /// P::DeleteKey(p).fold(P::SendInitiation(p)); // panic
    /// ```
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, PeerPtr};
    ///
    /// let p = PeerPtr(0);
    ///
    /// use PollResult as P;
    /// assert!(matches!(P::Sleep(10.0).fold(P::Sleep(20.0)), P::Sleep(10.0)));
    /// assert!(matches!(P::DeleteKey(p).fold(P::Sleep(20.0)), P::DeleteKey(_)));
    /// assert!(matches!(P::Sleep(10.0).fold(P::SendInitiation(p)), P::SendInitiation(_)));
    /// ```
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

    /// Like [Self::fold], but takes function to conditionally execute,
    /// supports error handling, and safely handles the case that both
    /// poll results may be [Self::saturated], by never calling the given
    /// function if this is saturated.
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, PeerPtr};
    ///
    /// let p = PeerPtr(0);
    ///
    /// use PollResult as P;
    /// assert!(matches!(P::Sleep(50.0).try_fold_with(|| Ok(P::Sleep(20.0)))?, P::Sleep(20.0)));
    /// assert!(matches!(P::DeleteKey(p).try_fold_with(|| Ok(P::Sleep(20.0)))?, P::DeleteKey(_)));
    /// assert!(matches!(P::Sleep(10.0).try_fold_with(|| Ok(P::SendInitiation(p)))?, P::SendInitiation(_)));
    /// assert!(matches!(P::DeleteKey(p).try_fold_with(|| Ok(P::SendInitiation(p)))?, P::DeleteKey(_)));
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
    pub fn try_fold_with<F: FnOnce() -> Result<PollResult>>(&self, f: F) -> Result<PollResult> {
        if self.saturated() {
            Ok(*self)
        } else {
            Ok(self.fold(f()?))
        }
    }

    /// This is specifically made to invoke the [Pollable::poll] function when recursively checking
    /// objects that might need polling.
    ///
    /// # Examples
    ///
    /// The best place to see this in action is the source code of [PeerPtr::poll]
    pub fn poll_child<P: Pollable>(&self, srv: &mut CryptoServer, p: &P) -> Result<PollResult> {
        self.try_fold_with(|| p.poll(srv))
    }

    /// This is specifically made to invoke the [Pollable::poll] function when recursively checking
    /// lists of objects that might need polling.
    ///
    /// # Examples
    ///
    /// The best place to see this in action is the source code of [PeerPtr::poll]
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

    /// Execute the given polling function at a particular point.
    ///
    /// The function ignores the polling function if [Self] is [Self::saturated].
    ///
    /// The function returns an appropriate [Self::Sleep] value if wait is greater than zero.
    ///
    /// The function executes the polling function only if wait smaller or equal to zero, modulo
    /// [has_happened].
    ///
    /// # Examples
    ///
    /// The best place to see this in action is the source code of [PeerPtr::poll]
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, PeerPtr};
    ///
    /// let p = PeerPtr(0);
    ///
    /// use PollResult as P;
    /// assert!(matches!(P::Sleep(50.0).sched(0.0, || P::Sleep(20.0)), P::Sleep(20.0)));
    /// assert!(matches!(P::Sleep(50.0).sched(60.0, || P::Sleep(20.0)), P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).sched(50.0, || P::Sleep(20.0)), P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).sched(40.0, || P::Sleep(20.0)), P::Sleep(40.0)));
    ///
    /// assert!(matches!(P::Sleep(50.0).sched(0.0, || P::DeleteKey(p)), P::DeleteKey(p)));
    /// assert!(matches!(P::Sleep(50.0).sched(60.0, || P::DeleteKey(p)), P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).sched(50.0, || P::DeleteKey(p)), P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).sched(40.0, || P::DeleteKey(p)), P::Sleep(40.0)));
    ///
    /// assert!(matches!(P::DeleteKey(p).sched(0.0, || P::SendInitiation(p)), P::DeleteKey(p)));
    /// assert!(matches!(P::DeleteKey(p).sched(10.0, || P::SendInitiation(p)), P::DeleteKey(p)));
    /// ```
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

    /// Like [Self::sched], but supports error handling with Result
    ///
    /// # Examples
    ///
    /// The best place to see this in action is the source code of [PeerPtr::poll]
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, PeerPtr};
    ///
    /// let p = PeerPtr(0);
    ///
    /// use PollResult as P;
    /// assert!(matches!(P::Sleep(50.0).try_sched(0.0, || Ok(P::Sleep(20.0)))?, P::Sleep(20.0)));
    /// assert!(matches!(P::Sleep(50.0).try_sched(60.0, || Ok(P::Sleep(20.0)))?, P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).try_sched(50.0, || Ok(P::Sleep(20.0)))?, P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).try_sched(40.0, || Ok(P::Sleep(20.0)))?, P::Sleep(40.0)));
    ///
    /// assert!(matches!(P::Sleep(50.0).try_sched(0.0, || Ok(P::DeleteKey(p)))?, P::DeleteKey(p)));
    /// assert!(matches!(P::Sleep(50.0).try_sched(60.0, || Ok(P::DeleteKey(p)))?, P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).try_sched(50.0, || Ok(P::DeleteKey(p)))?, P::Sleep(50.0)));
    /// assert!(matches!(P::Sleep(50.0).try_sched(40.0, || Ok(P::DeleteKey(p)))?, P::Sleep(40.0)));
    ///
    /// assert!(matches!(P::DeleteKey(p).try_sched(0.0, || Ok(P::SendInitiation(p)))?, P::DeleteKey(p)));
    /// assert!(matches!(P::DeleteKey(p).try_sched(10.0, || Ok(P::SendInitiation(p)))?, P::DeleteKey(p)));
    ///
    /// Ok::<(), anyhow::Error>(())
    /// ```
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

    /// Convenience function to wrap a PollResult into a Result
    ///
    /// # Examples
    ///
    /// The best place to see this in action is the source code of [PeerPtr::poll]
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult};
    ///
    /// use PollResult as P;
    /// assert!(matches!(P::Sleep(50.0).ok(), Ok(P::Sleep(50.0))));
    /// ```
    pub fn ok(&self) -> Result<PollResult> {
        Ok(*self)
    }

    /// A poll-result is considered to be saturated if it is something
    /// other than [Self::Sleep]
    ///
    /// # Examples
    ///
    /// ```
    /// use rosenpass::protocol::{PollResult, PeerPtr};
    ///
    /// let p = PeerPtr(0);
    ///
    /// use PollResult as P;
    /// assert!(!P::Sleep(0.0).saturated());
    /// assert!(!P::Sleep(50.0).saturated());
    /// assert!(P::DeleteKey(p).saturated());
    /// assert!(P::SendRetransmission(p).saturated());
    /// assert!(P::SendInitiation(p).saturated());
    /// ```
    pub fn saturated(&self) -> bool {
        use PollResult::*;
        !matches!(self, Sleep(_))
    }
}

/// Semantic wrapper around [PollResult::default]
///
/// # Examples
///
/// ```
/// use rosenpass::protocol::{begin_poll, PollResult, timing::UNENDING};
///
/// assert!(matches!(begin_poll(), PollResult::Sleep(UNENDING)));
/// ```
pub fn begin_poll() -> PollResult {
    PollResult::default()
}

/// Takes a closure `f`, returns another closure which internally calls f and
/// then returns a default [PollResult]
///
/// This is a convenience function in order to be able to encode side_effects in
/// the polling process.
///
/// # Examples
///
/// The best place to see this in action is the source code of [PeerPtr::poll]
///
/// ```
/// use rosenpass::protocol::{begin_poll, void_poll, PollResult, PeerPtr};
///
/// let mut x = 0;
///
/// let poll_result = begin_poll()
///     .sched(20.0, void_poll(|| { x += 100 }))
///     .sched(0.0, void_poll(|| { x += 10 }))
///     .sched(0.0, void_poll(|| { x += 10 }))
///     .sched(0.0, void_poll(|| { x += 10 }))
///     .fold(PollResult::SendInitiation(PeerPtr(0)))
///     .sched(0.0, void_poll(|| { x += 1 }));
/// assert!(matches!(poll_result, PollResult::SendInitiation(_)));
/// assert_eq!(x, 30);
/// ```
pub fn void_poll<T, F: FnOnce() -> T>(f: F) -> impl FnOnce() -> PollResult {
    || {
        f();
        PollResult::default()
    }
}

/// Implemented for types that should be polled during recursive polling in [CryptoServer::poll]
pub trait Pollable {
    /// Poll this!
    ///
    /// # Examples
    ///
    /// The best place to see this in action is the source code of [PeerPtr::poll]
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult>;
}

impl CryptoServer {
    /// Poll the CryptoServer for new events
    ///
    /// Handles all timing based events produced in the course of executing the Rosenpass
    /// protocol such as:
    ///
    /// - Cycling of biscuit and cookie keys ([CryptoServer::biscuit_keys] and
    ///   [CryptoServer::cookie_secrets])
    /// - Scheduling of initiation key exchanges and key renegotiations ([PollResult::SendInitiation])
    /// - Scheduling of message retransmission ([PollResult::SendRetransmission])
    /// - Scheduling of key erasure ([PollResult::DeleteKey])
    ///
    /// The correct way to use CryptoServer in production environments is to first
    /// call poll and then react to the instructions issued by poll. [PollResult] documents
    /// the actions that should be taken by the caller depending on the PollResult's value.
    /// documents
    /// the actions that should be taken by the caller depending on the PollResult's value.
    ///
    /// This is similar to [Pollable::poll] for the server, with a
    /// notable difference: since `self` already is the server, the signature
    /// has to be different; `self` must be a `&mut` and already is a borrow to
    /// the server, eluding the need for a second arg.
    ///
    /// # Examples
    ///
    /// Here is a complete example of how to use poll. It is written as a comprehensive integration
    /// test providing transcript based testing of the rosenpass, showcasing how to set up an event
    /// handling system integrating rosenpass.
    ///
    /// This is a lot of code. If you want to read the file outside of the documentation,
    /// check out `rosenpass/tests/poll_example.rs" in the repository.
    ///
    #[doc = "```ignore"]
    #[doc = include_str!("../../tests/poll_example.rs")]
    #[doc = "```"]
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
            .poll_child(srv, &hs)? // Defer to the handshake for polling (retransmissions)
            .poll_child(srv, &self.known_init_conf_response())
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

impl Pollable for KnownInitConfResponsePtr {
    fn poll(&self, srv: &mut CryptoServer) -> Result<PollResult> {
        begin_poll()
            // Erase stale cache
            .sched(self.life_left(srv), void_poll(|| self.remove(srv)))
            .ok()
    }
}

// MESSAGE RETRANSMISSION ////////////////////////

impl CryptoServer {
    /// Retransmits the current initiator-role handshake for the given peer.
    ///
    /// This should usually be called after [Self::poll] returns a
    /// [PollResult::SendRetransmission].
    ///
    /// # Examples
    ///
    /// For a full example of how to use the crypto server, including how to process retransmission
    /// handling, see the example in [Self::poll].
    pub fn retransmit_handshake(&mut self, peer: PeerPtr, tx_buf: &mut [u8]) -> Result<usize> {
        peer.hs().apply_retransmission(self, tx_buf)
    }
}

impl IniHsPtr {
    /// Store a protocol message for retransmission in initiator mode.
    ///
    /// This is called by [CryptoServer::initiate_handshake] and [CryptoServer::handle_msg]
    /// after producing an [InitHello] or [InitConf] message.
    ///
    /// # Examples
    ///
    /// This is internal business logic. Please refer to the source code of [CryptoServer::initiate_handshake] and [CryptoServer::handle_msg].
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

    /// [CryptoServer::retransmit_handshake] forwards this. You should use the function in
    /// CryptoServer instead of this one.
    ///
    /// # Examples
    ///
    /// This is considered to be internal logic.
    ///
    /// See the examples and the source code of [CryptoServer::retransmit_handshake].
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

    /// Internal business logic; used to register the fact that a retransmission has happened.
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
                * (rand::random::<f64>() + 1.0);
        ih.tx_count += 1;
        Ok(())
    }

    /// Internal business logic; used to register the fact that an immediate retransmission
    /// has happened in response to a [CookieReply] message
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

    /// Internal business logic: Indicates when the next retransmission of the message
    /// stored for the peer will happen
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
    /// Internal business logic: Calculate the message authentication code (`mac`) and also append cookie value
    pub fn seal(&mut self, peer: PeerPtr, srv: &CryptoServer) -> Result<()> {
        let mac = hash_domains::mac(peer.get(srv).protocol_version.keyed_hash())?
            .mix(peer.get(srv).spkt.deref())?
            .mix(&self.as_bytes()[span_of!(Self, msg_type..mac)])?;
        self.mac.copy_from_slice(mac.into_value()[..16].as_ref());
        self.seal_cookie(peer, srv)?;
        Ok(())
    }

    /// Internal business logic: Calculate and append the cookie value if `cookie_key` exists (`cookie`)
    ///
    /// This is called inside [Self::seal] and does not need to be called again separately.
    pub fn seal_cookie(&mut self, peer: PeerPtr, srv: &CryptoServer) -> Result<()> {
        if let Some(cookie_key) = &peer.cv().get(srv) {
            let cookie = hash_domains::cookie(KeyedHash::keyed_shake256())?
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
    /// Internal business logic: Check the message authentication code produced by [Self::seal]
    pub fn check_seal(&self, srv: &CryptoServer, shake_or_blake: KeyedHash) -> Result<bool> {
        let expected = hash_domains::mac(shake_or_blake)?
            .mix(srv.spkm.deref())?
            .mix(&self.as_bytes()[span_of!(Self, msg_type..mac)])?;
        Ok(constant_time::memcmp(
            &self.mac,
            &expected.into_value()[..16],
        ))
    }
}

impl InitiatorHandshake {
    /// Zero initialization of an InitiatorHandshake, with up to date timestamp
    pub fn zero_with_timestamp(srv: &CryptoServer, keyed_hash: KeyedHash) -> Self {
        InitiatorHandshake {
            created_at: srv.timebase.now(),
            next: HandshakeStateMachine::RespHello,
            core: HandshakeState::zero(keyed_hash),
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
    /// Zero initialization of an HandshakeState
    pub fn zero(keyed_hash: KeyedHash) -> Self {
        Self {
            sidi: SessionId::zero(),
            sidr: SessionId::zero(),
            ck: SecretHashDomain::zero(keyed_hash).dup(),
        }
    }

    /// Securely erase the chaining key
    pub fn erase(&mut self) {
        self.ck = SecretHashDomain::zero(self.ck.keyed_hash().clone()).dup();
    }

    /// Initialize the handshake state with the responder public key and the protocol domain
    /// separator
    pub fn init(&mut self, spkr: &[u8]) -> Result<&mut Self> {
        self.ck = hash_domains::ckinit(self.ck.keyed_hash().clone())?
            .turn_secret()
            .mix(spkr)?
            .dup();
        Ok(self)
    }

    /// Mix some data into the chaining key. This is used for mixing cryptographic keys and public
    /// data alike into the chaining key
    pub fn mix(&mut self, a: &[u8]) -> Result<&mut Self> {
        self.ck = self
            .ck
            .mix(&hash_domains::mix(self.ck.keyed_hash().clone())?)?
            .mix(a)?
            .dup();
        Ok(self)
    }

    /// Encrypt some data with a value derived from the current chaining key and mix that data
    /// into the protocol state.
    pub fn encrypt_and_mix(&mut self, ct: &mut [u8], pt: &[u8]) -> Result<&mut Self> {
        let k = self
            .ck
            .mix(&hash_domains::hs_enc(self.ck.keyed_hash().clone())?)?
            .into_secret();
        ensure!(Aead::NONCE_LEN == 12);
        Aead.encrypt(ct, k.secret(), &[0u8; 12], &[], pt)?;
        self.mix(ct)
    }

    /// Decryption counterpart to [Self::encrypt_and_mix].
    ///
    /// Makes sure that the same values are mixed into the chaining that where mixed in on the
    /// sender side.
    pub fn decrypt_and_mix(&mut self, pt: &mut [u8], ct: &[u8]) -> Result<&mut Self> {
        let k = self
            .ck
            .mix(&hash_domains::hs_enc(self.ck.keyed_hash().clone())?)?
            .into_secret();
        ensure!(Aead::NONCE_LEN == 12);
        Aead.decrypt(pt, k.secret(), &[0u8; 12], &[], ct)?;
        self.mix(ct)
    }

    /// Encapsulate a secret with a KEM and mix the resulting secret into the chaining key.
    ///
    /// The ciphertext must be transmitted to the other party.
    ///
    /// This is used to include asymmetric cryptography in the rosenpass protocol
    // I loathe "error: constant expression depends on a generic parameter"
    pub fn encaps_and_mix<
        const KEM_SK_LEN: usize,
        const KEM_PK_LEN: usize,
        const KEM_CT_LEN: usize,
        const KEM_SHK_LEN: usize,
        KemImpl: Kem<KEM_SK_LEN, KEM_PK_LEN, KEM_CT_LEN, KEM_SHK_LEN>,
    >(
        &mut self,
        kem: &KemImpl,
        ct: &mut [u8; KEM_CT_LEN],
        pk: &[u8; KEM_PK_LEN],
    ) -> Result<&mut Self> {
        let mut shk = Secret::<KEM_SHK_LEN>::zero();
        kem.encaps(shk.secret_mut(), ct, pk)?;
        self.mix(pk)?.mix(shk.secret())?.mix(ct)
    }

    /// Decapsulation (decryption) counterpart to [Self::encaps_and_mix].
    ///
    /// Makes sure that the same values are mixed into the chaining that where mixed in on the
    /// sender side.
    pub fn decaps_and_mix<
        const KEM_SK_LEN: usize,
        const KEM_PK_LEN: usize,
        const KEM_CT_LEN: usize,
        const KEM_SHK_LEN: usize,
        KemImpl: Kem<KEM_SK_LEN, KEM_PK_LEN, KEM_CT_LEN, KEM_SHK_LEN>,
    >(
        &mut self,
        kem: &KemImpl,
        sk: &[u8; KEM_SK_LEN],
        pk: &[u8; KEM_PK_LEN],
        ct: &[u8; KEM_CT_LEN],
    ) -> Result<&mut Self> {
        let mut shk = Secret::<KEM_SHK_LEN>::zero();
        kem.decaps(shk.secret_mut(), sk, ct)?;
        self.mix(pk)?.mix(shk.secret())?.mix(ct)
    }

    /// Store the chaining key inside a cookie value called a "biscuit".
    ///
    /// This biscuit can be transmitted to the other party and must be returned
    /// by them on the next protocol message.
    ///
    /// This is used to store the responder state between [InitHello] and [InitConf] processing
    /// to make sure the responder is stateless.
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
        let ad = hash_domains::biscuit_ad(peer.get(srv).protocol_version.keyed_hash())?
            .mix(srv.spkm.deref())?
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
        XAead.encrypt_with_nonce_in_ctxt(biscuit_ct, k, &*n, &ad, pt)?;

        self.mix(biscuit_ct)
    }

    /// This is the counterpart to [Self::store_biscuit] that restores a stored biscuit
    pub fn load_biscuit(
        srv: &CryptoServer,
        biscuit_ct: &[u8],
        sidi: SessionId,
        sidr: SessionId,
        shake_or_blake: KeyedHash,
    ) -> Result<(PeerPtr, BiscuitId, HandshakeState)> {
        // The first bit of the biscuit indicates which biscuit key was used
        let bk = BiscuitKeyPtr(((biscuit_ct[0] & 0b1000_0000) >> 7) as usize);

        // Calculate additional data fields
        let ad = hash_domains::biscuit_ad(shake_or_blake)?
            .mix(srv.spkm.deref())?
            .mix(sidi.as_slice())?
            .mix(sidr.as_slice())?
            .into_value();

        // Allocate and decrypt the biscuit data
        let mut biscuit = Secret::<BISCUIT_PT_LEN>::zero(); // pt buf
        let mut biscuit: Ref<&mut [u8], Biscuit> =
            Ref::new(biscuit.secret_mut().as_mut_slice()).unwrap();
        XAead.decrypt_with_nonce_in_ctxt(
            biscuit.as_bytes_mut(),
            bk.get(srv).value.secret(),
            &ad,
            biscuit_ct,
        )?;

        // Reconstruct the biscuit fields
        let no = BiscuitId::from_slice(&biscuit.biscuit_no);
        let pid = PeerId::from_slice(&biscuit.pidi);
        // Look up the associated peer
        let peer = srv
            .find_peer(pid) // TODO: FindPeer should return a Result<()>
            .with_context(|| format!("Could not decode biscuit for peer {pid:?}: No such peer."))?;

        let ck = SecretHashDomain::danger_from_secret(
            Secret::from_slice(&biscuit.ck),
            peer.get(srv).protocol_version.keyed_hash(),
        )
        .dup();
        // Reconstruct the handshake state
        let mut hs = Self { sidi, sidr, ck };
        hs.mix(biscuit_ct)?;

        Ok((peer, no, hs))
    }

    /// Initialize a [Session] after the key exchange was completed
    ///
    /// This called by either party.
    ///
    /// `role` indicates whether the local peer was an initiator or responder in the handshake.
    pub fn enter_live(
        self,
        srv: &CryptoServer,
        role: HandshakeRole,
        either_shake_or_blake: KeyedHash,
    ) -> Result<Session> {
        let HandshakeState { ck, sidi, sidr } = self;
        let tki = ck
            .mix(&hash_domains::ini_enc(either_shake_or_blake.clone())?)?
            .into_secret();
        let tkr = ck
            .mix(&hash_domains::res_enc(either_shake_or_blake)?)?
            .into_secret();
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
    /// Variant of [Self::osk] that allows a custom, already compressed domain separator to be specified
    ///
    /// Refer to the documentation of [Self::osk] for more information.
    pub fn osk_with_compressed_domain_separator(
        &self,
        peer: PeerPtr,
        compressed_domain_separator: &PublicSymKey,
    ) -> Result<SymKey> {
        let session = peer
            .session()
            .get(self)
            .as_ref()
            .with_context(|| format!("No current session for peer {:?}", peer))?;

        Ok(session.ck.mix(compressed_domain_separator)?.into_secret())
    }

    /// Variant of [Self::osk] that allows a custom domain separator to be specified
    ///
    /// Refer to the documentation of [Self::osk] for more information.
    pub fn osk_with_domain_separator(
        &self,
        peer: PeerPtr,
        domain_separator: &OskDomainSeparator,
    ) -> Result<SymKey> {
        let hash_choice = peer.get(self).protocol_version.keyed_hash();
        let compressed_domain_separator = domain_separator.compress_with(hash_choice)?;
        self.osk_with_compressed_domain_separator(peer, &compressed_domain_separator)
    }

    /// Get the shared key that was established with given peer
    ///
    /// Fail if no session is available with the peer
    ///
    /// # See also
    ///
    /// - [Self::osk_with_domain_separator]
    /// - [Self::osk_with_compressed_domain_separator]
    ///
    /// # Examples
    ///
    /// See the example in [crate::protocol] for an incomplete but working example
    /// of how to perform a key exchange using Rosenpass.
    ///
    /// See the example in [CryptoServer::poll] for a complete example.
    ///
    /// See the documentation and examples in [super::osk_domain_separator] for more information
    /// about using custom domain separators.
    pub fn osk(&self, peer: PeerPtr) -> Result<SymKey> {
        let hash_choice = peer.get(self).protocol_version.keyed_hash();
        let compressed_domain_separator = peer
            .get(self)
            .osk_domain_separator
            .compress_with(hash_choice)?;
        self.osk_with_compressed_domain_separator(peer, &compressed_domain_separator)
    }
}

/// Marks a section of the protocol using the same identifiers as are used in the whitepaper.
/// When building with the trace benchmarking feature enabled, this also emits span events into the
/// trace, which allows reconstructing the run times of the individual sections for performance
/// measurement.
macro_rules! protocol_section {
    ($label:expr, $body:block) => {{
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span($label);

        #[allow(unused_braces)]
        $body
    }};
}

impl CryptoServer {
    /// Core cryptographic protocol implementation: Kicks of the handshake
    /// on the initiator side, producing the InitHello message.
    pub fn handle_initiation(&mut self, peer: PeerPtr, ih: &mut InitHello) -> Result<PeerPtr> {
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span("handle_initiation");

        let mut hs = InitiatorHandshake::zero_with_timestamp(
            self,
            peer.get(self).protocol_version.keyed_hash(),
        );

        // IHI1
        protocol_section!("IHI1", {
            hs.core.init(peer.get(self).spkt.deref())?;
        });

        // IHI2
        protocol_section!("IHI2", {
            hs.core.sidi.randomize();
            ih.sidi.copy_from_slice(&hs.core.sidi.value);
        });

        // IHI3
        protocol_section!("IHI3", {
            EphemeralKem.keygen(hs.eski.secret_mut(), &mut *hs.epki)?;
            ih.epki.copy_from_slice(&hs.epki.value);
        });

        // IHI4
        protocol_section!("IHI4", {
            hs.core.mix(ih.sidi.as_slice())?.mix(ih.epki.as_slice())?;
        });

        // IHI5
        protocol_section!("IHI5", {
            hs.core
                .encaps_and_mix(&StaticKem, &mut ih.sctr, peer.get(self).spkt.deref())?;
        });

        // IHI6
        protocol_section!("IHI6", {
            hs.core.encrypt_and_mix(
                ih.pidic.as_mut_slice(),
                self.pidm(peer.get(self).protocol_version.keyed_hash())?
                    .as_ref(),
            )?;
        });

        // IHI7
        protocol_section!("IHI7", {
            hs.core
                .mix(self.spkm.deref())?
                .mix(peer.get(self).psk.secret())?;
        });

        // IHI8
        protocol_section!("IHI8", {
            hs.core.encrypt_and_mix(ih.auth.as_mut_slice(), &[])?;
        });

        // Update the handshake hash last (not changing any state on prior error
        peer.hs().insert(self, hs)?;

        Ok(peer)
    }

    /// Core cryptographic protocol implementation: Parses an [InitHello] message and produces a
    /// [RespHello] message on the responder side.
    pub fn handle_init_hello(
        &mut self,
        ih: &InitHello,
        rh: &mut RespHello,
        keyed_hash: KeyedHash,
    ) -> Result<PeerPtr> {
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span("handle_init_hello");

        let mut core = HandshakeState::zero(keyed_hash);

        core.sidi = SessionId::from_slice(&ih.sidi);

        // IHR1
        protocol_section!("IHR1", {
            core.init(self.spkm.deref())?;
        });

        // IHR4
        protocol_section!("IHR4", {
            core.mix(&ih.sidi)?.mix(&ih.epki)?;
        });

        // IHR5
        protocol_section!("IHR5", {
            core.decaps_and_mix(&StaticKem, self.sskm.secret(), self.spkm.deref(), &ih.sctr)?;
        });

        // IHR6
        let peer = protocol_section!("IHR6", {
            let mut peerid = PeerId::zero();
            core.decrypt_and_mix(&mut *peerid, &ih.pidic)?;
            self.find_peer(peerid)
                .with_context(|| format!("No such peer {peerid:?}."))?
        });

        // IHR7
        protocol_section!("IHR7", {
            core.mix(peer.get(self).spkt.deref())?
                .mix(peer.get(self).psk.secret())?;
        });

        // IHR8
        protocol_section!("IHR8", {
            core.decrypt_and_mix(&mut [0u8; 0], &ih.auth)?;
        });

        // RHR1
        protocol_section!("RHR1", {
            core.sidr.randomize();
            rh.sidi.copy_from_slice(core.sidi.as_ref());
            rh.sidr.copy_from_slice(core.sidr.as_ref());
        });

        // RHR3
        protocol_section!("RHR3", {
            core.mix(&rh.sidr)?.mix(&rh.sidi)?;
        });

        // RHR4
        protocol_section!("RHR4", {
            core.encaps_and_mix(&EphemeralKem, &mut rh.ecti, &ih.epki)?;
        });

        // RHR5
        protocol_section!("RHR5", {
            core.encaps_and_mix(&StaticKem, &mut rh.scti, peer.get(self).spkt.deref())?;
        });

        // RHR6
        protocol_section!("RHR6", {
            core.store_biscuit(self, peer, &mut rh.biscuit)?;
        });

        // RHR7
        protocol_section!("RHR7", {
            core.encrypt_and_mix(&mut rh.auth, &[])?;
        });

        Ok(peer)
    }

    /// Core cryptographic protocol implementation: Parses an [RespHello] message and produces an
    /// [InitConf] message on the initiator side.
    pub fn handle_resp_hello(&mut self, rh: &RespHello, ic: &mut InitConf) -> Result<PeerPtr> {
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span("handle_resp_hello");

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
        protocol_section!("RHI3", {
            core.mix(&rh.sidr)?.mix(&rh.sidi)?;
        });

        // RHI4
        protocol_section!("RHI4", {
            core.decaps_and_mix(
                &EphemeralKem,
                hs!().eski.secret(),
                hs!().epki.deref(),
                &rh.ecti,
            )?;
        });

        // RHI5
        protocol_section!("RHI5", {
            core.decaps_and_mix(&StaticKem, self.sskm.secret(), self.spkm.deref(), &rh.scti)?;
        });

        // RHI6
        protocol_section!("RHI6", {
            core.mix(&rh.biscuit)?;
        });

        // RHI7
        protocol_section!("RHI7", {
            core.decrypt_and_mix(&mut [0u8; 0], &rh.auth)?;
        });

        // TODO: We should just authenticate the entire network package up to the auth
        // tag as a pattern instead of mixing in fields separately

        ic.sidi.copy_from_slice(&rh.sidi);
        ic.sidr.copy_from_slice(&rh.sidr);

        // ICI3
        protocol_section!("ICI3", {
            core.mix(&ic.sidi)?.mix(&ic.sidr)?;
            ic.biscuit.copy_from_slice(&rh.biscuit);
        });

        // ICI4
        protocol_section!("ICI4", {
            core.encrypt_and_mix(&mut ic.auth, &[])?;
        });

        // Split() – We move the secrets into the session; we do not
        // delete the InitiatorHandshake, just clear it's secrets because
        // we still need it for InitConf message retransmission to function.

        // ICI7
        protocol_section!("ICI7", {
            peer.session().insert(
                self,
                core.enter_live(
                    self,
                    HandshakeRole::Initiator,
                    peer.get(self).protocol_version.keyed_hash(),
                )?,
            )?;
            hs_mut!().core.erase();
            hs_mut!().next = HandshakeStateMachine::RespConf;
        });

        Ok(peer)
    }

    /// Core cryptographic protocol implementation: Parses an [InitConf] message and produces an
    /// [EmptyData] (responder confirmation) message on the responder side.
    ///
    /// This concludes the handshake on the cryptographic level; the [EmptyData] message is just
    /// an acknowledgement message telling the initiator to stop performing retransmissions.
    pub fn handle_init_conf(
        &mut self,
        ic: &InitConf,
        rc: &mut EmptyData,
        keyed_hash: KeyedHash,
    ) -> Result<PeerPtr> {
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span("handle_init_conf");

        // (peer, bn) ← LoadBiscuit(InitConf.biscuit)
        // ICR1
        let (peer, biscuit_no, mut core) = protocol_section!("ICR1", {
            HandshakeState::load_biscuit(
                self,
                &ic.biscuit,
                SessionId::from_slice(&ic.sidi),
                SessionId::from_slice(&ic.sidr),
                keyed_hash,
            )?
        });

        // ICR2
        protocol_section!("ICR2", {
            core.encrypt_and_mix(&mut [0u8; Aead::TAG_LEN], &[])?;
        });

        // ICR3
        protocol_section!("ICR3", {
            core.mix(&ic.sidi)?.mix(&ic.sidr)?;
        });

        // ICR4
        protocol_section!("ICR4", {
            core.decrypt_and_mix(&mut [0u8; 0], &ic.auth)?;
        });

        // ICR5
        // Defense against replay attacks; implementations may accept
        // the most recent biscuit no again (bn = peer.bn_{prev}) which
        // indicates retransmission
        ensure!(
            constant_time::compare(&*biscuit_no, &*peer.get(self).biscuit_used) > 0,
            "Rejecting biscuit: Outdated biscuit number"
        );

        // ICR6
        protocol_section!("ICR6", {
            peer.get_mut(self).biscuit_used = biscuit_no;
        });

        // ICR7
        protocol_section!("ICR7", {
            peer.session().insert(
                self,
                core.enter_live(
                    self,
                    HandshakeRole::Responder,
                    peer.get(self).protocol_version.keyed_hash(),
                )?,
            )?;
            // TODO: This should be part of the protocol specification.
            // Abort any ongoing handshake from initiator role
            peer.hs().take(self);
        });

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
        // because data transmission is a stub currently.
        let ses = peer
            .session()
            .get_mut(self)
            .as_mut()
            .context("Cannot send acknowledgement. No session.")?;
        rc.sid.copy_from_slice(&ses.sidt.value);
        rc.ctr.copy_from_slice(&ses.txnm.to_le_bytes());
        ses.txnm += 1; // Increment nonce before encryption, just in case an error is raised

        let n = cat!(Aead::NONCE_LEN; &rc.ctr, &[0u8; 4]);
        let k = ses.txkm.secret();
        Aead.encrypt(&mut rc.auth, k, &n, &[], &[])?; // ct, k, n, ad, pt

        Ok(peer)
    }

    /// Core cryptographic protocol implementation: Parses an [EmptyData] (responder confirmation)
    /// message then terminates the handshake.
    ///
    /// The EmptyData message is just there to tell the initiator to abort retransmissions.
    pub fn handle_resp_conf(
        &mut self,
        msg_in: &Ref<&[u8], Envelope<EmptyData>>,
        seal_broken: String,
    ) -> Result<PeerPtr> {
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span("handle_resp_conf");

        let rc: &EmptyData = &msg_in.payload;
        let sid = SessionId::from_slice(&rc.sid);
        let hs = self
            .lookup_handshake(sid)
            .with_context(|| format!("Got RespConf packet for non-existent session {sid:?}"))?;
        ensure!(
            msg_in.check_seal(self, hs.peer().get(self).protocol_version.keyed_hash())?,
            seal_broken
        );
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
            // the unwrapping can not fail, because the slice returned by ctr() is
            // guaranteed to have the correct size
            let n = u64::from_le_bytes(rc.ctr);
            ensure!(n >= s.txnt, "Stale nonce");
            s.txnt = n;
            Aead.decrypt(
                // pt, k, n, ad, ct
                &mut [0u8; 0],
                s.txkt.secret(),
                &cat!(Aead::NONCE_LEN; &rc.ctr, &[0u8; 4]),
                &[],
                &rc.auth,
            )?;
        }

        // We can now stop retransmitting RespConf
        hs.take(self);

        Ok(hs.peer())
    }

    /// Core protocol implementation: This is not part of the cryptographic handshake itself,
    /// instead this function is used to process [CookieReply] messages which is part of Rosenpass'
    /// DOS mitigation features.
    ///
    /// See more on DOS mitigation in Rosenpass in the [whitepaper](https://rosenpass.eu/whitepaper.pdf).
    pub fn handle_cookie_reply(&mut self, cr: &CookieReply) -> Result<PeerPtr> {
        #[cfg(feature = "trace_bench")]
        let _span_guard = rosenpass_util::trace_bench::trace().emit_span("handle_cookie_reply");

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

                let spkt = peer.get(self).spkt.deref();
                let cookie_key = hash_domains::cookie_key(KeyedHash::keyed_shake256())?
                    .mix(spkt)?
                    .into_value();
                let cookie_value = peer.cv().update_mut(self).unwrap();

                XAead.decrypt_with_nonce_in_ctxt(
                    cookie_value,
                    &cookie_key,
                    &mac,
                    &cr.inner.cookie_encrypted,
                )?;

                // Immediately retransmit on receiving a cookie reply message
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
