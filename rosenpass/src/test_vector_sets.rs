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
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub shk: TestValue<Secret<KEM_SHK_LEN>>,
}

#[derive(TestVectorSet)]
pub struct StoreBiscuitTestValues {
    #[test_vec(serialize_with = "serialize_byte_vec")]
    #[test_vec(deserialize_with = "deserialize_byte_vec")]
    pub biscuit: TestValue<Vec<u8>>,

    #[test_vec(serialize_with = "serialize_public")]
    #[test_vec(deserialize_with = "deserialize_public")]
    pub n: TestValue<Public<{ XAead::NONCE_LEN }>>,

    #[test_vec(serialize_with = "serialize_byte_vec")]
    #[test_vec(deserialize_with = "deserialize_byte_vec")]
    pub biscuit_ct: TestValue<Vec<u8>>,
}

#[derive(TestVectorSet)]
pub struct HandleInitiationTestValues {
    #[test_vec(name = "hs.cookie_value.value")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_cookie: TestValue<Secret<COOKIE_VALUE_LEN>>,

    #[test_vec(name = "hs.core.sidi")]
    #[test_vec(serialize_with = "serialize_public")]
    #[test_vec(deserialize_with = "deserialize_public")]
    pub init_handshake_sidi: TestValue<Public<SESSION_ID_LEN>>,

    #[test_vec(name = "hs.eski")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_eski: TestValue<Secret<{ EphemeralKem::SK_LEN }>>,

    #[test_vec(name = "hs.core.ck")]
    #[test_vec(serialize_with = "serialize_public")]
    #[test_vec(deserialize_with = "deserialize_public")]
    pub init_handshake_epki: TestValue<Public<{ EphemeralKem::PK_LEN }>>,

    #[test_vec(name = "hs.core.ck 1")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_mix_1: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "hs.core.ck 2")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_mix_2: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "ih.pidic")]
    #[test_vec(serialize_with = "serialize_byte_arr")]
    #[test_vec(deserialize_with = "deserialize_byte_arr")]
    pub init_hello_pidic: TestValue<[u8; rosenpass_ciphers::Aead::TAG_LEN + 32]>,

    #[test_vec(name = "hs.core.ck 3")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_mix_3: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "hs.core.ck 4")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_mix_4: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "ih.auth")]
    #[test_vec(serialize_with = "serialize_byte_arr")]
    #[test_vec(deserialize_with = "deserialize_byte_arr")]
    pub init_hello_auth: TestValue<[u8; rosenpass_ciphers::Aead::TAG_LEN]>,

    #[test_vec(name = "hs.core.ck 5")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub init_handshake_mix_5: TestValue<Secret<KEY_LEN>>,
}

#[derive(TestVectorSet)]
pub struct HandleInitHelloTestValues {
    #[test_vec(name = "chaining_key_ihr IHR 4")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_ihr_4: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 5")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_ihr_5: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 6")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_ihr_6: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 7")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_ihr_7: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr IHR 8")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_ihr_8: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "session_id")]
    #[test_vec(serialize_with = "serialize_public")]
    #[test_vec(deserialize_with = "deserialize_public")]
    pub session_id: TestValue<SessionId>,

    #[test_vec(name = "chaining_key_ihr RHR 3")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_rhr_3: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 4")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_rhr_4: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 5")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_rhr_5: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 6")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub chaining_key_rhr_6: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "chaining_key_ihr RHR 7")]
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
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
    #[test_vec(serialize_with = "serialize_secret")]
    #[test_vec(deserialize_with = "deserialize_secret")]
    pub cycled_biscuit_secret_key: TestValue<Secret<KEY_LEN>>,
}

pub fn serialize_secret<const N: usize>(observed_value: &Secret<N>) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(observed_value.secret());
    Ok(Value::String(encoded))
}

pub fn deserialize_secret<const N: usize>(value: &Value) -> anyhow::Result<Secret<N>> {
    let value: &str = value
        .as_str()
        .ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
    Ok(Secret::<N>::from_slice(decoded.as_slice()))
}

pub fn serialize_public_box<const N: usize>(
    observed_value: &PublicBox<N>,
) -> anyhow::Result<Value> {
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(observed_value.inner.value.as_slice());
    Ok(Value::String(encoded))
}

pub fn deserialize_public_box<const N: usize>(value: &Value) -> anyhow::Result<PublicBox<N>> {
    let value: &str = value
        .as_str()
        .ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
    let mut trg = Box::new(Public::<N>::zero());
    trg.copy_from_slice(decoded.as_slice());
    let trg = PublicBox { inner: trg };
    Ok(trg)
}

pub fn serialize_public<const N: usize>(observed_value: &Public<N>) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(observed_value.value.as_slice());
    Ok(Value::String(encoded))
}

pub fn deserialize_public<const N: usize>(value: &Value) -> anyhow::Result<Public<N>> {
    let value: &str = value
        .as_str()
        .ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
    Ok(Public::<N>::from_slice(decoded.as_slice()))
}

pub fn serialize_byte_arr<const N: usize>(observed_value: &[u8; N]) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(observed_value);
    Ok(Value::String(encoded))
}

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

pub fn serialize_byte_vec(observed_value: &Vec<u8>) -> anyhow::Result<Value> {
    let encoded = base64::engine::general_purpose::STANDARD.encode(observed_value);
    Ok(Value::String(encoded))
}

pub fn deserialize_byte_vec(value: &Value) -> anyhow::Result<Vec<u8>> {
    let value: &str = value
        .as_str()
        .ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(value.as_bytes())
        .map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
    Ok(decoded)
}
