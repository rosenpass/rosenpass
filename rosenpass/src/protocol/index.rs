//! Quick lookup of values in [super::CryptoServer]

use std::collections::HashMap;

use super::basic_types::{PeerId, PeerNo, SessionId};
use super::KnownResponseHash;

/// Maps various keys to peer (numbers).
///
/// See:
/// - [super::CryptoServer::index]
/// - [super::CryptoServer::peers]
/// - [PeerNo]
/// - [super::PeerPtr]
/// - [super::Peer]
pub type PeerIndex = HashMap<PeerIndexKey, PeerNo>;

/// We maintain various indices in [super::CryptoServer::index], mapping some key to a particular
/// [PeerNo], i.e. to an index in [super::CryptoServer::peers]. These are the possible index key.
#[derive(Hash, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum PeerIndexKey {
    /// Lookup of a particular peer given the [PeerId], i.e. a value derived from the peers public
    /// key as created by [super::CryptoServer::pidm] or [super::Peer::pidt].
    ///
    /// The peer id is used by the initiator to tell the responder about its identity in
    /// [crate::msgs::InitHello].
    ///
    /// See also the pointer types [super::PeerPtr].
    Peer(PeerId),
    /// Lookup of a particular session id.
    ///
    /// This is used to look up both established sessions (see
    /// [super::CryptoServer::lookup_session]) and ongoing handshakes (see [super::CryptoServer::lookup_handshake]).
    ///
    /// Lookup of a peer to get an established session or a handshake is sufficient, because a peer
    /// contains a limited number of sessions and handshakes ([super::Peer::session] and [super::Peer::handshake] respectively).
    ///
    /// See also the pointer types [super::IniHsPtr] and [super::SessionPtr].
    Sid(SessionId),
    /// Lookup of a cached response ([crate::msgs::Envelope]<[crate::msgs::EmptyData]>) to an [crate::msgs::InitConf] (i.e.
    /// [crate::msgs::Envelope]<[crate::msgs::InitConf]>) message.
    ///
    /// See [super::KnownInitConfResponsePtr] on how this value is maintained.
    KnownInitConfResponse(KnownResponseHash),
}
