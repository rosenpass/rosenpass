//! Test vector definitions for derandomizing protocol internals.
//!
//! This module contains the definitions of internal test vector values used by
//! `CryptoServer` and the functions in `protocol.rs`. These values allow the
//! protocol implementation to be derandomized for deterministic testing and
//! reproducible behavior across runs.
//!
//! For an example of a test that uses these test vector values, see:
//! `rosenpass/tests/test_vector_crypto_server.rs`.

use crate::msgs::SESSION_ID_LEN;
use crate::protocol::basic_types::SessionId;
use crate::protocol::constants::COOKIE_VALUE_LEN;
use anyhow::anyhow;
use assert_tv::TestValue;
use assert_tv::TestVectorSet;
use base64::Engine;
use rosenpass_cipher_traits::primitives::{Aead, Kem};
use rosenpass_ciphers::{EphemeralKem, XAead, KEY_LEN};
use rosenpass_secret_memory::{Public, PublicBox, Secret};
use serde_json::Value;

#[derive(TestVectorSet)]
pub struct EncapsAndMixTestValues<const KEM_CT_LEN: usize, const KEM_SHK_LEN: usize> {
    #[test_vec(serialize_with = "serialize_byte_arr")]
    #[test_vec(deserialize_with = "deserialize_byte_arr")]
    pub ct: TestValue<[u8; KEM_CT_LEN]>,
    pub shk: TestValue<Secret<KEM_SHK_LEN>>,
}

#[derive(TestVectorSet)]
pub struct StoreBiscuitTestValues {
    #[test_vec(serialize_with = "serialize_byte_vec")]
    #[test_vec(deserialize_with = "deserialize_byte_vec")]
    pub biscuit: TestValue<Vec<u8>>,

    pub n: TestValue<Public<{ XAead::NONCE_LEN }>>,

    #[test_vec(serialize_with = "serialize_byte_vec")]
    #[test_vec(deserialize_with = "deserialize_byte_vec")]
    pub biscuit_ct: TestValue<Vec<u8>>,
}

#[derive(TestVectorSet)]
pub struct HandleInitiationTestValues {
    #[test_vec(name = "hs.cookie_value.value")]
    pub init_handshake_cookie: TestValue<Secret<COOKIE_VALUE_LEN>>,

    #[test_vec(name = "hs.core.sidi")]
    pub init_handshake_sidi: TestValue<Public<SESSION_ID_LEN>>,

    #[test_vec(name = "hs.eski")]
    pub init_handshake_eski: TestValue<Secret<{ EphemeralKem::SK_LEN }>>,

    #[test_vec(name = "hs.core.ck")]
    pub init_handshake_epki: TestValue<Public<{ EphemeralKem::PK_LEN }>>,

    #[test_vec(name = "hs.core.ck 1")]
    pub init_handshake_mix_1: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "hs.core.ck 2")]
    pub init_handshake_mix_2: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "ih.pidic")]
    #[test_vec(serialize_with = "serialize_byte_arr")]
    #[test_vec(deserialize_with = "deserialize_byte_arr")]
    pub init_hello_pidic: TestValue<[u8; rosenpass_ciphers::Aead::TAG_LEN + 32]>,

    #[test_vec(name = "hs.core.ck 3")]
    pub init_handshake_mix_3: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "hs.core.ck 4")]
    pub init_handshake_mix_4: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "ih.auth")]
    #[test_vec(serialize_with = "serialize_byte_arr")]
    #[test_vec(deserialize_with = "deserialize_byte_arr")]
    pub init_hello_auth: TestValue<[u8; rosenpass_ciphers::Aead::TAG_LEN]>,

    #[test_vec(name = "hs.core.ck 5")]
    pub init_handshake_mix_5: TestValue<Secret<KEY_LEN>>,
}

#[derive(TestVectorSet)]
pub struct HandleInitHelloTestValues {
    #[test_vec(name = "chaining_key_ihr IHR 4")]
    pub chaining_key_ihr_4: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 5")]
    pub chaining_key_ihr_5: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 6")]
    pub chaining_key_ihr_6: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 7")]
    pub chaining_key_ihr_7: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 8")]
    pub chaining_key_ihr_8: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "session_id")]
    pub session_id: TestValue<SessionId>,

    #[test_vec(name = "chaining_key_ihr RHR 3")]
    pub chaining_key_rhr_3: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 4")]
    pub chaining_key_rhr_4: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 5")]
    pub chaining_key_rhr_5: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 6")]
    pub chaining_key_rhr_6: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 7")]
    pub chaining_key_rhr_7: TestValue<Secret<KEY_LEN>>,
}

#[derive(TestVectorSet)]
pub struct InitHandshakeTestValues {
    #[test_vec(serialize_with = "serialize_byte_vec")]
    #[test_vec(deserialize_with = "deserialize_byte_vec")]
    pub msg: TestValue<Vec<u8>>,
}

#[derive(TestVectorSet)]
pub struct CycledBiscuitSecretKeyTestValues {
    #[test_vec(name = "CryptoServer::biscuit_key[r]")]
    #[test_vec(description = "Biscuit key after being cycled")]
    pub cycled_biscuit_secret_key: TestValue<Secret<KEY_LEN>>,
}

// Serialization helpers for raw byte arrays and vectors.
//
// These functions provide a small bridge implementation to serialize/deserialize
// standard values that do not carry serde implementations with the desired
// base64 format by default. They are used by the test vector machinery to
// encode `[u8; N]` and `Vec<u8>` values consistently.

/// Serialize a byte array as a base64 JSON string (bridge for `[u8; N]`).
pub fn serialize_byte_arr<const N: usize>(observed_value: &[u8; N]) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(observed_value);
    Ok(Value::String(encoded))
}

/// Deserialize a base64 JSON string into a byte array (bridge for `[u8; N]`).
pub fn deserialize_byte_arr<const N: usize>(value: &Value) -> anyhow::Result<[u8; N]> {
    let value: &str = value
        .as_str()
        .ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
    decoded
        .as_slice()
        .try_into()
        .map_err(|e| anyhow!("Couldn't convert to array of size={}: {e}", N))
}

/// Serialize a byte vector as a base64 JSON string (bridge for `Vec<u8>`).
pub fn serialize_byte_vec(observed_value: &Vec<u8>) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(observed_value);
    Ok(Value::String(encoded))
}

/// Deserialize a base64 JSON string into a byte vector (bridge for `Vec<u8>`).
pub fn deserialize_byte_vec(value: &Value) -> anyhow::Result<Vec<u8>> {
    let value: &str = value
        .as_str()
        .ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
    Ok(decoded)
}
