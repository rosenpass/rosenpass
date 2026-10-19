//! Pseudo Random Functions (PRFs) with a tree-like label scheme which
//! ensures their uniqueness.
//!
//! This ensures [domain separation](https://en.wikipedia.org/wiki/Domain_separation) is used
//! across the Rosenpass protocol.
//!
//! There is a chart containing all hash domains used in Rosenpass in the
//! [whitepaper](https://rosenpass.eu/whitepaper.pdf) ([/papers/whitepaper.md] in this repository).
//!
//! # Tutorial
//!
#![cfg_attr(feature = "expose_internal_modules", doc = "```")]
#![cfg_attr(not(feature = "expose_internal_modules"), doc = "```ignore")]
//! use rosenpass::{hash_domain, hash_domain_ns};
//! use rosenpass::hash_domains::protocol;
//! use rosenpass::internal::ciphers::EphemeralKem;
//! use rosenpass::internal::ciphers::KeyedHash;
//!
//! // Declaring a custom hash domain
//! hash_domain_ns!(protocol, custom_domain, "my custom hash domain label");
//!
//! // Declaring custom hashers
//! hash_domain_ns!(custom_domain, hashers, "hashers");
//! hash_domain_ns!(hashers, hasher1, "1");
//! hash_domain_ns!(hashers, hasher2, "2");
//!
//! // Declaring specific domain separators
//! hash_domain_ns!(custom_domain, domain_separators, "domain separators");
//! hash_domain!(domain_separators, sep1, "1");
//! hash_domain!(domain_separators, sep2, "2");
//!
//! // We use the SHAKE256 hash function and Kyber 512 ephemeral KEM for this example
//! let hash_choice = KeyedHash::keyed_shake256();
//! let ekem_choice = EphemeralKem::Kyber512Round3;
//!
//! // Generating values under hasher1 with both domain separators
//! let h1 = hasher1(hash_choice.clone(), ekem_choice)?.mix(b"some data")?.dup();
//! let h1v1 = h1.mix(&sep1(hash_choice.clone(), ekem_choice)?)?.mix(b"More data")?.into_value();
//! let h1v2 = h1.mix(&sep2(hash_choice.clone(), ekem_choice)?)?.mix(b"More data")?.into_value();
//!
//! // Generating values under hasher2 with both domain separators
//! let h2 = hasher2(hash_choice.clone(), ekem_choice)?.mix(b"some data")?.dup();
//! let h2v1 = h2.mix(&sep1(hash_choice.clone(), ekem_choice)?)?.mix(b"More data")?.into_value();
//! let h2v2 = h2.mix(&sep2(hash_choice.clone(), ekem_choice)?)?.mix(b"More data")?.into_value();
//!
//! // All of the domain separators are now different, random strings
//! let values = [h1v1, h1v2, h2v1, h2v2];
//! for i in 0..values.len() {
//!     for j in (i+1)..values.len() {
//!         assert_ne!(values[i], values[j]);
//!     }
//! }
//!
//! Ok::<(), anyhow::Error>(())
//! ```

use crate::internal::ciphers::{EphemeralKem, KeyedHash, hash_domain::HashDomain};
use anyhow::Result;

/// Declare a hash function
///
/// # Examples
///
/// See the source file for details about how this is used concretely.
///
/// See the [module](self) documentation on how to use the hash domains in general
// TODO Use labels that can serve as identifiers
#[macro_export]
macro_rules! hash_domain_ns {
    ($(#[$($attrss:tt)*])* $base:ident, $name:ident, $($lbl:expr),+ ) => {
        $(#[$($attrss)*])*
        pub fn $name(hash_choice: KeyedHash, ekem_choice: $crate::internal::ciphers::EphemeralKem) -> ::anyhow::Result<$crate::internal::ciphers::hash_domain::HashDomain> {
            let t = $base(hash_choice, ekem_choice)?;
            $( let t = t.mix($lbl.as_bytes())?; )*
            Ok(t)
        }
    }
}

/// Declare a concrete hash value
///
/// # Examples
///
/// See the source file for details about how this is used concretely.
///
/// See the [module](self) documentation on how to use the hash domains in general
#[macro_export]
macro_rules! hash_domain {
    ($(#[$($attrss:tt)*])* $base:ident, $name:ident, $($lbl:expr),+ ) => {
        $(#[$($attrss)*])*
        pub fn $name(hash_choice: KeyedHash, ekem_choice: $crate::internal::ciphers::EphemeralKem) -> ::anyhow::Result<[u8; $crate::internal::ciphers::KEY_LEN]> {
            let t = $base(hash_choice, ekem_choice)?;
            $( let t = t.mix($lbl.as_bytes())?; )*
            Ok(t.into_value())
        }
    }
}

/// The hash domain containing the protocol string.
///
/// This serves as a global [domain separator](https://en.wikipedia.org/wiki/Domain_separation)
/// used in various places in the rosenpass protocol.
///
/// This is generally used to create further hash-domains for specific purposes (e.g. [`mac`], [`cookie`], [`peerid`]).
/// Depending on the used hash function and the chosen ephemeral KEM, the protocol string is different.
///
/// # Examples
///
/// See the source file for details about how this is used concretely.
///
/// See the [module](self) documentation on how to use the hash domains in general.
pub fn protocol(hash_choice: KeyedHash, ephemeral_kem_choice: EphemeralKem) -> Result<HashDomain> {
    let hash_string = hash_choice.protocol_string_hash_id();
    let ekem_string = ephemeral_kem_choice.protocol_string_kem_id();
    HashDomain::zero(hash_choice).mix(
        format!("Rosenpass v1 mceliece460896 {ekem_string} ChaChaPoly1305 {hash_string}")
            .as_bytes(),
    )
}

hash_domain_ns!(
    /// Hash domain based on [protocol] for calculating [crate::msgs::Envelope::mac].
    ///
    /// # Examples
    ///
    /// See the source of [crate::msgs::Envelope::seal] and [crate::msgs::Envelope::check_seal] 
    /// to figure out how this is concretely used.
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, mac, "mac");
hash_domain_ns!(
    /// Hash domain based on [protocol] involved in calculating [crate::msgs::Envelope::cookie].
    ///
    /// # Examples
    ///
    /// See the source of [crate::msgs::Envelope::seal_cookie],
    /// [crate::protocol::CryptoServer::handle_msg_under_load], and
    /// [crate::protocol::CryptoServer::handle_cookie_reply]
    /// to figure out how this is concretely used.
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, cookie, "cookie");
hash_domain_ns!(
    /// Hash domain based on [protocol] involved in calculating [crate::msgs::Envelope::cookie].
    ///
    /// # Examples
    ///
    /// See the source of [crate::msgs::Envelope::seal_cookie],
    /// [crate::protocol::CryptoServer::handle_msg_under_load], and
    /// [crate::protocol::CryptoServer::handle_cookie_reply]
    /// to figure out how this is concretely used.
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, cookie_value, "cookie-value");
hash_domain_ns!(
    /// Hash domain based on [protocol] involved in calculating [crate::msgs::Envelope::cookie].
    ///
    /// # Examples
    ///
    /// See the source of [crate::msgs::Envelope::seal_cookie],
    /// [crate::protocol::CryptoServer::handle_msg_under_load], and
    /// [crate::protocol::CryptoServer::handle_cookie_reply]
    /// to figure out how this is concretely used.
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, cookie_key, "cookie-key");
hash_domain_ns!(
    /// Hash domain based on [protocol] for calculating the peer id as transmitted (encrypted)
    /// in [crate::msgs::InitHello::pidi_ct].
    ///
    /// # Examples
    ///
    /// See the source of [crate::protocol::CryptoServer::pidm] and
    /// [crate::protocol::Peer::pidt]
    /// to figure out how this is concretely used.
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, peerid, "peer id");
hash_domain_ns!(
    /// Hash domain based on [protocol] for calculating the additional data
    /// during [crate::msgs::Biscuit] encryption, storing the biscuit into
    /// [crate::msgs::RespHello::biscuit_ct].
    ///
    /// # Examples
    ///
    /// To understand how the biscuit is used, it is best to read
    /// the code of [crate::protocol::HandshakeState::store_biscuit] and
    /// [crate::protocol::HandshakeState::load_biscuit]
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, biscuit_ad, "biscuit additional data");
hash_domain_ns!(
    /// This hash domain begins our actual handshake procedure, initializing the
    /// chaining key [crate::protocol::HandshakeState::ck]. 
    ///
    /// # Examples
    ///
    /// To understand how the chaining key is used, study
    /// [crate::protocol::HandshakeState], especially [crate::protocol::HandshakeState::init]
    /// and [crate::protocol::HandshakeState::mix].
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, ckinit, "chaining key init");
hash_domain_ns!(
    /// Namespace for chaining key usage domain separators.
    ///
    /// During the execution of the Rosenpass protocol, we use the chaining key for multiple
    /// purposes, so to make sure that we have unique value domains, we mix a domain separator
    /// into the chaining key before using it for any particular purpose.
    ///
    /// We could use the full domain separation strings, but using a hash value here is nice
    /// because it does not lead to any constraints about domain separator format and we can
    /// even allow third parties to define their own separators by claiming a namespace.
    ///
    /// # Examples
    ///
    /// To understand how the chaining key is used, study
    /// [crate::protocol::HandshakeState], especially [crate::protocol::HandshakeState::init]
    /// and [crate::protocol::HandshakeState::mix].
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// # Parameters
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    protocol, _ckextract, "chaining key extract");

hash_domain!(
    /// Used to mix in further values into the chaining key during the handshake.
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// To understand how the chaining key is used, study
    /// [crate::protocol::HandshakeState], especially [crate::protocol::HandshakeState::init]
    /// and [crate::protocol::HandshakeState::mix].
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    _ckextract, mix, "mix");
hash_domain!(
    /// Chaining key domain separator for generating encryption keys that can
    /// encrypt parts of the handshake.
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// Encryption of data during the handshake happens in
    /// [crate::protocol::HandshakeState::encrypt_and_mix] and decryption happens in
    /// [crate::protocol::HandshakeState::decrypt_and_mix]. See their source code
    /// for details.
    ///
    /// To understand how the chaining key is used, study
    /// [crate::protocol::HandshakeState], especially [crate::protocol::HandshakeState::init]
    /// and [crate::protocol::HandshakeState::mix].
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    _ckextract, hs_enc, "handshake encryption");
hash_domain!(
    /// Chaining key domain separator for live data encryption.
    /// Live data encryption is only used to send confirmation of handshake
    /// done in [crate::msgs::EmptyData].
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// This domain separator finds use in [crate::protocol::HandshakeState::enter_live].
    ///
    /// To understand how the chaining key is used, study
    /// [crate::protocol::HandshakeState], especially [crate::protocol::HandshakeState::init]
    /// and [crate::protocol::HandshakeState::mix].
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    _ckextract, ini_enc, "initiator handshake encryption");
hash_domain!(
    /// Chaining key domain separator for live data encryption.
    /// Live data encryption is only used to send confirmation of handshake
    /// done in [crate::msgs::EmptyData].
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// This domain separator finds use in [crate::protocol::HandshakeState::enter_live].
    /// Check out its source code!
    ///
    /// To understand how the chaining key is used, study
    /// [crate::protocol::HandshakeState], especially [crate::protocol::HandshakeState::init]
    /// and [crate::protocol::HandshakeState::mix].
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// Parameters:
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    _ckextract, res_enc, "responder handshake encryption");

hash_domain_ns!(
    /// Chaining key domain separator for any usage specific purposes.
    ///
    /// We do recommend that third parties base their specific domain separators
    /// on a internet domain and/or mix in much more specific information.
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// # Parameters
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    _ckextract, cke_user, "user");
hash_domain_ns!(
    /// Chaining key domain separator for any rosenpass specific purposes.
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// # Parameters
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    cke_user, cke_user_rosenpass, "rosenpass.eu");
hash_domain!(
    /// Chaining key domain separator for deriving the key sent to WireGuard.
    ///
    /// See [_ckextract].
    ///
    /// # Examples
    ///
    /// This domain separator finds use in [crate::protocol::CryptoServer::osk].
    /// Check out its source code!
    ///
    /// See the [module](self) documentation on how to use the hash domains in general.
    ///
    /// # Parameters
    /// - `hash_choice`: the hash function chosen for the protocol, see type `KeyedHash` for valid values
    /// - `ekem_choice`: the ephemeral KEM chosen for the protocol, see type `EphemeralKem` for valid values"
    cke_user_rosenpass, ext_wireguard_psk_osk, "wireguard psk");

hash_domain_ns!(
    /// domain for the protocol context (`ctx`) mixed into the chaining key
    /// at protocol steps IHI7/IHR7
    protocol, context, "context");
hash_domain_ns!(
    /// domain for the protocol context (without "output")
    context, protocol_context, "protocol context");
hash_domain_ns!(
    /// domain for the protocol context (with "output")
    protocol_context, protocol_context_output, "output");
hash_domain_ns!(
    /// domain for the mutual protocol context token `ctxc`
    protocol_context, protocol_context_common, "common");
hash_domain_ns!(
    /// domain for the initiator's protocol context token `ctxi`
    protocol_context, protocol_context_initiator, "initiator");
hash_domain_ns!(
    /// domain for the responder's protocol context token `ctxr`
    protocol_context, protocol_context_responder, "responder");
hash_domain_ns!(
    /// domain for additional data mixed into the protocol context.
    context, additional_data, "additional data");
hash_domain_ns!(
    /// domain for user-specified additional data
    additional_data, additional_data_user, "user");
hash_domain_ns!(
    /// domain for the mutual user additional data `adc`
    additional_data_user, additional_data_user_common, "common");
hash_domain_ns!(
    /// domain for the initiator's user additional data `adi`
    additional_data_user, additional_data_user_initiator, "initiator");
hash_domain_ns!(
    /// domain for the responder's user additional data `adr`
    additional_data_user, additional_data_user_responder, "responder");
