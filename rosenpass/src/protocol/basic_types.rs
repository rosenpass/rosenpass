//! Key types and other fundamental types used in the Rosenpass protocol

use rosenpass_cipher_traits::primitives::{Aead, Kem};
use rosenpass_ciphers::{EphemeralKem, StaticKem, XAead, KEY_LEN};
use rosenpass_secret_memory::{Public, PublicBox, Secret};

use crate::msgs::{BISCUIT_ID_LEN, MAX_MESSAGE_LEN, SESSION_ID_LEN};

/// Static public key
///
/// Using [PublicBox] instead of [Public] because Classic McEliece keys are very large.
pub type SPk = PublicBox<{ StaticKem::PK_LEN }>;
/// Static secret key
pub type SSk = Secret<{ StaticKem::SK_LEN }>;
/// Ephemeral public key
pub type EPk = Public<{ EphemeralKem::PK_LEN }>;
pub type ESk = Secret<{ EphemeralKem::SK_LEN }>;

/// Symmetric key
pub type SymKey = Secret<KEY_LEN>;
/// Variant of [SymKey] for use cases where the value is public
pub type PublicSymKey = [u8; 32];

/// Peer ID (derived from the public key, see the hash derivations in the [whitepaper](https://rosenpass.eu/whitepaper.pdf))
pub type PeerId = Public<KEY_LEN>;
/// Session ID
pub type SessionId = Public<SESSION_ID_LEN>;
/// Biscuit ID
pub type BiscuitId = Public<BISCUIT_ID_LEN>;

/// Nonce for use with random-nonce AEAD
pub type XAEADNonce = Public<{ XAead::NONCE_LEN }>;

/// Buffer capably of holding any Rosenpass protocol message
pub type MsgBuf = Public<MAX_MESSAGE_LEN>;

/// Server-local peer number; this is just the index in [super::CryptoServer::peers]
pub type PeerNo = usize;
