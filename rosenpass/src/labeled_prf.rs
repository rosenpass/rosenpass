//! Pseudo Random Functions (PRFs) with a tree-like label scheme which
//! ensures their uniqueness

use {
    crate::{prftree::PrfTree, sodium::KEY_SIZE},
    anyhow::Result,
};

const PROTOCOL : &str = "rosenpass 1 rosenpass.eu aead=chachapoly1305 hash=blake2s ekem=kyber512 skem=mceliece460896 xaead=xchachapoly1305";

pub fn protocol() -> Result<PrfTree> {
    PrfTree::zero().mix(PROTOCOL.as_bytes())
}

// TODO Use labels that can serve as identifiers
macro_rules! prflabel {
    ($base:ident, $name:ident, $($lbl:expr),* ) => {
        pub fn $name() -> Result<PrfTree> {
            let t = $base()?;
            $( let t = t.mix($lbl.as_bytes())?; )*
            Ok(t)
        }
    }
}

prflabel!(protocol, mac, "mac");
prflabel!(protocol, cookie, "cookie");
prflabel!(protocol, peerid, "peer id");
prflabel!(protocol, biscuit_ad, "biscuit additional data");
prflabel!(protocol, ckinit, "chaining key init");
prflabel!(protocol, _ckextract, "chaining key extract");

macro_rules! prflabel_leaf {
    ($base:ident, $name:ident, $($lbl:expr),* ) => {
        pub fn $name() -> Result<[u8; KEY_SIZE]> {
            let t = $base()?;
            $( let t = t.mix($lbl.as_bytes())?; )*
            Ok(t.into_value())
        }
    }
}

prflabel_leaf!(_ckextract, mix, "mix");
prflabel_leaf!(_ckextract, hs_enc, "handshake encryption");
prflabel_leaf!(_ckextract, ini_enc, "initiator handshake encryption");
prflabel_leaf!(_ckextract, res_enc, "responder handshake encryption");

prflabel!(_ckextract, _user, "user");
prflabel!(_user, _rp, "rosenpass.eu");
prflabel_leaf!(_rp, osk, "wireguard psk");
