//! Pseudo Random Functions (PRFs) with a tree-like label scheme which
//! ensures their uniqueness

use crate::prftree::PrfTree;
use log::{error, info};
use thiserror::Error;
use rosenpass_ciphers::KEY_LEN;

// Define a custom error type using the thiserror crate
#[derive(Debug, Error)]
pub enum PrfError {
    #[error(transparent)]
    LogError(#[from] log::SetLoggerError),

    #[error("An error occurred: {0}")]
    CustomError(String),
}

impl From<PrfError> for log::SetLoggerError {
    fn from(error: PrfError) -> Self {
        log::SetLoggerError::Other(Box::new(error))
    }
}

pub fn protocol() -> Result<PrfTree, PrfError> {
    info!("Initializing protocol");
    let tree = PrfTree::zero().mix("Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s".as_bytes())?;
    Ok(tree)
}

// TODO Use labels that can serve as identifiers
macro_rules! prflabel {
    ($base:ident, $name:ident, $($lbl:expr),* ) => {
        pub fn $name() -> Result<PrfTree, PrfError> {
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
        pub fn $name() -> Result<[u8; KEY_LEN], PrfError> {
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
