//! Cryptographic key management for cookies and biscuits used in the protocol
//!
//! Cookies in general are conceptually similar to browser cookies;
//! i.e. mechanisms to store information in the party connected to via network.
//!
//! In our case specifically we refer to any mechanisms in the Rosenpass protocol
//! where a peer stores some information in the other party that is cryptographically
//! protected using a temporary, randomly generated key. This file contains the mechanisms
//! used to store the secret keys.
//!
//! We have two cookie-mechanisms in particular:
//!
//! - Rosenpass "biscuits" — the mechanism used to make sure the Rosenpass protocol is stateless
//!   with respect to the responder
//! - WireGuard's cookie mechanism to enable proof of IP ownership; Rosenpass has experimental
//!   support for this mechanism
//!
//! The CookieStore type is also used to store cookie secrets sent from the responder to the
//! initiator. This is a bad design and we should separate out this functionality.
//!
//! TODO: CookieStore should not be used for cookie secrets sent from responder to initiator.
//! TODO: Move cookie lifetime management functionality into here

use crate::internal::ciphers::KEY_LEN;
use crate::internal::secret_memory::Secret;

use super::timing::Timing;

/// container for storing cookie secrets like [BiscuitKey]
///
/// This is really just a secret key and a time stamp of creation. Concrete
/// usages (such as for the biscuit key) impose a time limit about how long
/// a key can be used and the time of creation is used to impose that time limit.
///
/// # Examples
///
/// ```ignore
#[doc=include_str!("../../tests/protocol_cookies_CookieStore.rs")]
/// ```
#[derive(Debug)]
pub struct CookieStore<const N: usize> {
    /// Time of creation of the secret key
    pub created_at: Timing,
    /// The secret key
    pub value: Secret<N>,
}
/// Storage for our biscuit keys.
///
/// The biscuit keys encrypt what we call "biscuits".
/// These biscuits contain the responder state for a particular handshake. By moving
/// state into these biscuits, we make sure the responder is stateless.
///
/// A Biscuit is like a fancy cookie. To avoid state disruption attacks,
/// the responder doesn't store state. Instead the state is stored in a
/// Biscuit, that is encrypted using the [BiscuitKey] which is only known to
/// the Responder. Thus secrecy of the Responder state is not violated, still
/// the responder can avoid storing this state.
///
/// Concrete value is in [super::CryptoServer::biscuit_keys].
///
/// The pointer type is [super::BiscuitKeyPtr].
pub type BiscuitKey = CookieStore<KEY_LEN>;
