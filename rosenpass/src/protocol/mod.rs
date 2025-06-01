//! Module containing the cryptographic protocol implementation
//!
//! # Overview
//!
//! The most important types in this module probably are [PollResult]
//! & [CryptoServer]. Once a [CryptoServer] is created, the server is
//! provided with new messages via the [CryptoServer::handle_msg] method.
//! The [CryptoServer::poll] method can be used to let the server work, which
//! will eventually yield a [PollResult]. Said [PollResult] contains
//! prescriptive activities to be carried out. [CryptoServer::osk] can than
//! be used to extract the shared key for two peers, once a key-exchange was
//! successful.
//!
//! TODO explain briefly the role of epki
//!
//! # Example Handshake
//!
//! This example illustrates a minimal setup for a key-exchange between two
//! [CryptoServer]s; this is what we use for some testing purposes but it is not
//! what should be used in a real world application, as timing-based events
//! are handled by [CryptoServer::poll].
//!
//! See [CryptoServer::poll] on how to use crypto server in polling mode for production usage.
//!
//! ```
//! use std::ops::DerefMut;
//! use rosenpass_secret_memory::policy::*;
//! use rosenpass_cipher_traits::primitives::Kem;
//! use rosenpass_ciphers::StaticKem;
//! use rosenpass::protocol::basic_types::{SSk, SPk, MsgBuf, SymKey};
//! use rosenpass::protocol::{PeerPtr, CryptoServer};
//! # fn main() -> anyhow::Result<()> {
//! // Set security policy for storing secrets
//!
//! use rosenpass::protocol::ProtocolVersion;
//! secret_policy_try_use_memfd_secrets();
//!
//! // initialize secret and public key for peer a ...
//! let (mut peer_a_sk, mut peer_a_pk) = (SSk::zero(), SPk::zero());
//! StaticKem.keygen(peer_a_sk.secret_mut(), peer_a_pk.deref_mut())?;
//!
//! // ... and for peer b
//! let (mut peer_b_sk, mut peer_b_pk) = (SSk::zero(), SPk::zero());
//! StaticKem.keygen(peer_b_sk.secret_mut(), peer_b_pk.deref_mut())?;
//!
//! // initialize server and a pre-shared key
//! let psk = SymKey::random();
//! let mut a = CryptoServer::new(peer_a_sk, peer_a_pk.clone());
//! let mut b = CryptoServer::new(peer_b_sk, peer_b_pk.clone());
//!
//! // introduce peers to each other
//! a.add_peer(Some(psk.clone()), peer_b_pk, ProtocolVersion::V03)?;
//! b.add_peer(Some(psk), peer_a_pk, ProtocolVersion::V03)?;
//!
//! // declare buffers for message exchange
//! let (mut a_buf, mut b_buf) = (MsgBuf::zero(), MsgBuf::zero());
//!
//! // let a initiate a handshake
//! let mut maybe_len = Some(a.initiate_handshake(PeerPtr(0), a_buf.as_mut_slice())?);
//!
//! // let a and b communicate
//! while let Some(len) = maybe_len {
//!    maybe_len = b.handle_msg(&a_buf[..len], &mut b_buf[..])?.resp;
//!    std::mem::swap(&mut a, &mut b);
//!    std::mem::swap(&mut a_buf, &mut b_buf);
//! }
//!
//! // all done! Extract the shared keys and ensure they are identical
//! let a_key = a.osk(PeerPtr(0))?;
//! let b_key = b.osk(PeerPtr(0))?;
//! assert_eq!(a_key.secret(), b_key.secret(),
//!     "the key exchanged failed to establish a shared secret");
//! # Ok(())
//! # }
//! ```

mod build_crypto_server;
pub use build_crypto_server::*;

pub mod basic_types;
pub mod constants;
pub mod cookies;
pub mod testutils;
pub mod timing;
pub mod zerocopy;

#[allow(clippy::module_inception)]
mod protocol;
pub use protocol::*;

#[cfg(test)]
mod test;
