//! Helpers used in tests

use std::ops::DerefMut;

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;

use super::{
    basic_types::{SPk, SSk},
    CryptoServer, PeerPtr, ProtocolVersion,
};

/// Helper for tests and examples
pub struct ServerForTesting {
    pub peer: PeerPtr,
    pub peer_keys: (SSk, SPk),
    pub srv: CryptoServer,
}

/// TODO: Document that the protocol version is only used for creating the peer for testing
impl ServerForTesting {
    pub fn new(protocol_version: ProtocolVersion) -> anyhow::Result<Self> {
        let (mut sskm, mut spkm) = (SSk::zero(), SPk::zero());
        StaticKem.keygen(sskm.secret_mut(), spkm.deref_mut())?;
        let mut srv = CryptoServer::new(sskm, spkm);

        let (mut sskt, mut spkt) = (SSk::zero(), SPk::zero());
        StaticKem.keygen(sskt.secret_mut(), spkt.deref_mut())?;
        let peer = srv.add_peer(None, spkt.clone(), protocol_version)?;

        let peer_keys = (sskt, spkt);
        Ok(ServerForTesting {
            peer,
            peer_keys,
            srv,
        })
    }

    pub fn tuple(self) -> (PeerPtr, (SSk, SPk), CryptoServer) {
        (self.peer, self.peer_keys, self.srv)
    }
}

/// Time travel forward in time
pub fn time_travel_forward(srv: &mut CryptoServer, secs: f64) {
    let dur = std::time::Duration::from_secs_f64(secs);
    srv.timebase.0 = srv.timebase.0.checked_sub(dur).unwrap();
}
