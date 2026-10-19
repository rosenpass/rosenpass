//! derivation of the protocol context (`ctx`) mixed into the chaining key at
//! protocol steps IHI7/IHR7
//!
//! See the whitepaper section on the protocol context for more information.

use std::ops::Deref;

use anyhow::Result;

use crate::hash_domains;
use crate::internal::ciphers::{EphemeralKem, KeyedHash};

use super::basic_types::{PublicSymKey, SPk, SymKey};

/// domain-separator labels of the **WireGuard protocol extension**
///
/// These are not used without the WireGuard protocol extension.
const WG_EXT_LABELS: [&str; 2] = ["rosenpass.eu", "wireguard psk"];

/// the specific WireGuard public keys to which the key exchange is bound
/// in the **WireGuard protocol extension**
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WireGuardKeyBinding {
    /// `wg_spkm` (WireGuard Static Public Key Mine)
    pub our_wg_pubkey: PublicSymKey,
    /// `wg_spkt` (WireGuard STatic Publick Key Theirs)
    pub peer_wg_pubkey: PublicSymKey,
}

/// protocol context (`ctx`) of a peer
#[derive(Clone, Debug)]
pub struct PeerProtocolContext {
    /// use this if we are the initiator
    pub as_initiator: SymKey,

    /// use this if we are the responder
    pub as_responder: SymKey,
}

impl PeerProtocolContext {
    /// zero-initialized context (used by [`crate::protocol::protocol::Peer::zero`])
    pub fn zero() -> Self {
        Self {
            as_initiator: SymKey::zero(),
            as_responder: SymKey::zero(),
        }
    }

    /// [`PeerProtocolContext`] for older protocol versions (v02) is simply the
    /// PSK set by the user
    pub fn from_psk(psk: &SymKey) -> Self {
        Self {
            as_initiator: psk.clone(),
            as_responder: psk.clone(),
        }
    }

    /// derive [`PeerProtocolContext`] (protocol v03 and newer)
    pub fn derive(
        psk: &SymKey,
        spkm: &SPk,
        spkt: &SPk,
        wg: Option<WireGuardKeyBinding>,
        keyed_hash: KeyedHash,
        ephemeral_kem: EphemeralKem,
    ) -> Result<Self> {
        Ok(Self {
            as_initiator: Self::derive_for_one_role(
                psk,
                spkm,
                spkt,
                wg.map(|wg| (wg.our_wg_pubkey, wg.peer_wg_pubkey)),
                keyed_hash.clone(),
                ephemeral_kem,
            )?,
            as_responder: Self::derive_for_one_role(
                psk,
                spkt,
                spkm,
                wg.map(|wg| (wg.peer_wg_pubkey, wg.our_wg_pubkey)),
                keyed_hash,
                ephemeral_kem,
            )?,
        })
    }

    /// derive `ctx` for one role assignment (initiator/responder)
    ///
    /// Pseudocode from the whitepaper:
    /// ```text
    /// ctx  = lhash("context", "protocol context", "output", ctxc, ctxi, ctxr)
    /// ctxc = lhash("context", "protocol context", "common",    psk , adc)
    /// ctxi = lhash("context", "protocol context", "initiator", spki, adi)
    /// ctxr = lhash("context", "protocol context", "responder", spkr, adr)
    ///
    /// # without wg extension:
    /// adc = lhash("context", "additional data", "user", "common",    "rosenpass.eu", "wireguard psk", uadc…)
    /// adi = lhash("context", "additional data", "user", "initiator", "rosenpass.eu", "wireguard psk", wg_spki, uadi…)
    /// adr = lhash("context", "additional data", "user", "responder", "rosenpass.eu", "wireguard psk", wg_spkr, uadr…)
    ///
    /// # with wg extension:
    /// adc = lhash("context", "additional data", "user", "common",    "rosenpass.eu", "wireguard psk", uadc…)
    /// adi = lhash("context", "additional data", "user", "initiator", "rosenpass.eu", "wireguard psk", wg_spki, uadi…)
    /// adr = lhash("context", "additional data", "user", "responder", "rosenpass.eu", "wireguard psk", wg_spkr, uadr…)
    /// ```
    fn derive_for_one_role(
        psk: &SymKey,
        spki: &SPk,
        spkr: &SPk,
        wg: Option<(PublicSymKey, PublicSymKey)>, // (wg_spki, wg_spkr)
        keyed_hash: KeyedHash,
        ephemeral_kem: EphemeralKem,
    ) -> Result<SymKey> {
        // user-defined data
        // psk is read from function parameter `psk`
        let uadc: [&[u8]; 0] = []; // uadc is empty for now – a user might specify it later
        let uadi: [&[u8]; 0] = []; // uadi is empty for now – a user might specify it later
        let uadr: [&[u8]; 0] = []; // uadr is empty for now – a user might specify it later

        // adc
        let adc = hash_domains::additional_data_user_common(keyed_hash.clone(), ephemeral_kem)?
            .turn_secret();
        let adc = if wg.is_some() {
            adc.mix_many(WG_EXT_LABELS)?
        } else {
            adc
        };
        let adc = adc.mix_many(uadc)?.into_secret();

        // adi
        let adi = hash_domains::additional_data_user_initiator(keyed_hash.clone(), ephemeral_kem)?
            .turn_secret();
        let adi = match wg {
            Some((wg_spki, _)) => adi.mix_many(WG_EXT_LABELS)?.mix(&wg_spki)?,
            None => adi,
        };
        let adi = adi.mix_many(uadi)?.into_secret();

        // adr
        let adr = hash_domains::additional_data_user_responder(keyed_hash.clone(), ephemeral_kem)?
            .turn_secret();
        let adr = match wg {
            Some((_, wg_spkr)) => adr.mix_many(WG_EXT_LABELS)?.mix(&wg_spkr)?,
            None => adr,
        };
        let adr = adr.mix_many(uadr)?.into_secret();

        // ctxc
        let ctxc = hash_domains::protocol_context_common(keyed_hash.clone(), ephemeral_kem)?
            .turn_secret()
            .mix(psk.secret())?
            .mix_secret(adc)?
            .into_secret();

        // ctxi
        let ctxi = hash_domains::protocol_context_initiator(keyed_hash.clone(), ephemeral_kem)?
            .turn_secret()
            .mix(spki.deref())?
            .mix_secret(adi)?
            .into_secret();

        // ctxr
        let ctxr = hash_domains::protocol_context_responder(keyed_hash.clone(), ephemeral_kem)?
            .turn_secret()
            .mix(spkr.deref())?
            .mix_secret(adr)?
            .into_secret();

        // return
        Ok(
            hash_domains::protocol_context_output(keyed_hash, ephemeral_kem)?
                .turn_secret()
                .mix_secret(ctxc)?
                .mix_secret(ctxi)?
                .mix_secret(ctxr)?
                .into_secret(),
        )
    }
}
