use rosenpass_util::{
    build::Build,
    mem::{DiscardResultExt, SwapWithDefaultExt},
    result::ensure_or,
};
use thiserror::Error;

use super::{CryptoServer, PeerPtr, SPk, SSk, SymKey};

#[derive(Debug, Clone)]
pub struct Keypair {
    pub sk: SSk,
    pub pk: SPk,
}

// TODO: We need a named tuple derive
impl Keypair {
    pub fn new(sk: SSk, pk: SPk) -> Self {
        Self { sk, pk }
    }

    pub fn zero() -> Self {
        Self::new(SSk::zero(), SPk::zero())
    }

    pub fn random() -> Self {
        Self::new(SSk::random(), SPk::random())
    }

    pub fn from_parts(parts: (SSk, SPk)) -> Self {
        Self::new(parts.0, parts.1)
    }

    pub fn into_parts(self) -> (SSk, SPk) {
        (self.sk, self.pk)
    }
}

#[derive(Error, Debug)]
#[error("PSK already set in BuildCryptoServer")]
pub struct PskAlreadySet;

#[derive(Error, Debug)]
#[error("Keypair already set in BuildCryptoServer")]
pub struct KeypairAlreadySet;

#[derive(Error, Debug)]
#[error("Can not construct CryptoServer: Missing keypair")]
pub struct MissingKeypair;

#[derive(Debug, Default)]
pub struct BuildCryptoServer {
    pub keypair: Option<Keypair>,
    pub peers: Vec<PeerParams>,
}

impl Build<CryptoServer> for BuildCryptoServer {
    type Error = anyhow::Error;

    fn build(self) -> Result<CryptoServer, Self::Error> {
        let Some(Keypair { sk, pk }) = self.keypair else {
            return Err(MissingKeypair)?;
        };

        let mut srv = CryptoServer::new(sk, pk);

        for (idx, PeerParams { psk, pk }) in self.peers.into_iter().enumerate() {
            let PeerPtr(idx2) = srv.add_peer(psk, pk)?;
            assert!(idx == idx2, "Peer id changed during CryptoServer construction from {idx} to {idx2}. This is a developer error.")
        }

        Ok(srv)
    }
}

#[derive(Debug)]
pub struct PeerParams {
    pub psk: Option<SymKey>,
    pub pk: SPk,
}

impl BuildCryptoServer {
    pub fn new(keypair: Option<Keypair>, peers: Vec<PeerParams>) -> Self {
        Self { keypair, peers }
    }

    pub fn empty() -> Self {
        Self::new(None, Vec::new())
    }

    pub fn from_parts(parts: (Option<Keypair>, Vec<PeerParams>)) -> Self {
        Self {
            keypair: parts.0,
            peers: parts.1,
        }
    }

    pub fn take_parts(&mut self) -> (Option<Keypair>, Vec<PeerParams>) {
        (self.keypair.take(), self.peers.swap_with_default())
    }

    pub fn into_parts(mut self) -> (Option<Keypair>, Vec<PeerParams>) {
        self.take_parts()
    }

    pub fn with_keypair(&mut self, keypair: Keypair) -> Result<&mut Self, KeypairAlreadySet> {
        ensure_or(self.keypair.is_none(), KeypairAlreadySet)?;
        self.keypair.insert(keypair).discard_result();
        Ok(self)
    }

    pub fn with_added_peer(&mut self, psk: Option<SymKey>, pk: SPk) -> &mut Self {
        // TODO: Check here already whether peer was already added
        self.peers.push(PeerParams { psk, pk });
        self
    }

    pub fn add_peer(&mut self, psk: Option<SymKey>, pk: SPk) -> PeerPtr {
        let id = PeerPtr(self.peers.len());
        self.with_added_peer(psk, pk);
        id
    }

    pub fn emancipate(&mut self) -> Self {
        Self::from_parts(self.take_parts())
    }
}
