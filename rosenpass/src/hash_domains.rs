//! Pseudo Random Functions (PRFs) with a tree-like label scheme which
//! ensures their uniqueness

use anyhow::Result;
use rosenpass_ciphers::{hash_domain::HashDomain, KEY_LEN};

// TODO Use labels that can serve as identifiers
macro_rules! hash_domain_ns {
    ($base:ident, $name:ident, $($lbl:expr),* ) => {
        pub fn $name() -> Result<HashDomain> {
            let t = $base()?;
            $( let t = t.mix($lbl.as_bytes())?; )*
            Ok(t)
        }
    }
}

macro_rules! hash_domain {
    ($base:ident, $name:ident, $($lbl:expr),* ) => {
        pub fn $name() -> Result<[u8; KEY_LEN]> {
            let t = $base()?;
            $( let t = t.mix($lbl.as_bytes())?; )*
            Ok(t.into_value())
        }
    }
}

pub fn protocol() -> Result<HashDomain> {
    HashDomain::zero().mix("Rosenpass v1 mceliece460896 Kyber512 ChaChaPoly1305 BLAKE2s".as_bytes())
}

hash_domain_ns!(protocol, mac, "mac");
hash_domain_ns!(protocol, cookie, "cookie");
hash_domain_ns!(protocol, cookie_tau, "cookie-tau");
hash_domain_ns!(protocol, cookie_key, "cookie-tau");
hash_domain_ns!(protocol, peerid, "peer id");
hash_domain_ns!(protocol, biscuit_ad, "biscuit additional data");
hash_domain_ns!(protocol, ckinit, "chaining key init");
hash_domain_ns!(protocol, _ckextract, "chaining key extract");

hash_domain!(_ckextract, mix, "mix");
hash_domain!(_ckextract, hs_enc, "handshake encryption");
hash_domain!(_ckextract, ini_enc, "initiator handshake encryption");
hash_domain!(_ckextract, res_enc, "responder handshake encryption");

hash_domain_ns!(_ckextract, _user, "user");
hash_domain_ns!(_user, _rp, "rosenpass.eu");
hash_domain!(_rp, osk, "wireguard psk");
