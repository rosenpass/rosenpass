use crate::{Public, PublicBox, Secret};
use base64::Engine;
use serde::de::{Error as DeError, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

fn encode_b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

fn decode_b64(s: &str) -> Result<Vec<u8>, String> {
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| format!("Couldn't decode base64: {e}"))
}

struct B64BytesVisitor;

impl<'de> Visitor<'de> for B64BytesVisitor {
    type Value = Vec<u8>;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "a base64-encoded string")
    }

    fn visit_str<E: DeError>(self, v: &str) -> Result<Self::Value, E> {
        decode_b64(v).map_err(E::custom)
    }

    fn visit_string<E: DeError>(self, v: String) -> Result<Self::Value, E> {
        self.visit_str(&v)
    }
}

impl<const N: usize> Serialize for Secret<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(self.secret()))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Secret<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = deserializer.deserialize_string(B64BytesVisitor)?;
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "Unexpected length: got {}, expected {}",
                bytes.len(),
                N
            )));
        }
        // Copies from heap bytes into the internal storage;
        // no large stack temporaries.
        Ok(Secret::<N>::from_slice(bytes.as_slice()))
    }
}

impl<const N: usize> Serialize for Public<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(&self.value))
    }
}

impl<'de, const N: usize> Deserialize<'de> for Public<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = deserializer.deserialize_string(B64BytesVisitor)?;
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "Unexpected length: got {}, expected {}",
                bytes.len(),
                N
            )));
        }
        Ok(Public::<N>::from_slice(bytes.as_slice()))
    }
}

impl<const N: usize> Serialize for PublicBox<N> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&encode_b64(self.inner.value.as_slice()))
    }
}

impl<'de, const N: usize> Deserialize<'de> for PublicBox<N> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let bytes: Vec<u8> = deserializer.deserialize_string(B64BytesVisitor)?;
        if bytes.len() != N {
            return Err(D::Error::custom(format!(
                "Unexpected length: got {}, expected {}",
                bytes.len(),
                N
            )));
        }
        // Allocate Public<N> on the heap and copy bytes into it
        let mut inner = Box::new(Public::<N>::zero());
        inner.copy_from_slice(bytes.as_slice());
        Ok(PublicBox { inner })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::secret_policy_use_only_malloc_secrets;
    use serde::{de::DeserializeOwned, Serialize};
    use serde_json;

    // Generic helper: serialize to JSON, then deserialize back.
    fn roundtrip_json<T>(value: &T) -> T
    where
        T: Serialize + DeserializeOwned,
    {
        let json = serde_json::to_string(value).expect("serialize");
        serde_json::from_str::<T>(&json).expect("deserialize")
    }

    pub fn test_init_secret_memory_policy() {
        secret_policy_use_only_malloc_secrets();
    }

    #[test]
    fn secret_roundtrip_json() {
        test_init_secret_memory_policy();
        const N: usize = 32;
        let src = [0xABu8; N];
        let original = Secret::<N>::from_slice(&src);
        let recovered: Secret<N> = roundtrip_json(&original);
        assert_eq!(
            original.secret(),
            recovered.secret(),
            "Secret bytes must match after roundtrip"
        );
    }

    #[test]
    fn public_roundtrip_json() {
        const N: usize = 48;
        let src = [0x11u8; N];
        let original = Public::<N>::from_slice(&src);
        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: Public<N> = serde_json::from_str(&json).expect("deserialize");
        // Avoid relying on private fields: compare canonical serialization strings.
        let json2 = serde_json::to_string(&recovered).expect("re-serialize");
        assert_eq!(
            json, json2,
            "Public must serialize identically after roundtrip"
        );
    }

    #[test]
    fn public_box_roundtrip_json() {
        const N: usize = 64;
        let src = [0x7Fu8; N];

        let original = PublicBox::<N>::new(src);

        let json = serde_json::to_string(&original).expect("serialize");
        let recovered: PublicBox<N> = serde_json::from_str(&json).expect("deserialize");
        let json2 = serde_json::to_string(&recovered).expect("re-serialize");
        assert_eq!(
            json, json2,
            "PublicBox must serialize identically after roundtrip"
        );
    }

    #[test]
    fn secret_len_mismatch_is_error() {
        test_init_secret_memory_policy();
        const N_SMALL: usize = 16;
        const N_BIG: usize = 32;

        let src = [0x55u8; N_SMALL];
        let small = Secret::<N_SMALL>::from_slice(&src);
        let json = serde_json::to_string(&small).expect("serialize");

        // Attempt to deserialize a 16-byte payload into Secret<32> should fail.
        let res = serde_json::from_str::<Secret<N_BIG>>(&json);
        assert!(
            res.is_err(),
            "Deserializing into a larger fixed size must error"
        );
    }

    #[test]
    fn public_len_mismatch_is_error() {
        const N_SMALL: usize = 24;
        const N_BIG: usize = 40;

        let src = [0x33u8; N_SMALL];
        let small = Public::<N_SMALL>::from_slice(&src);
        let json = serde_json::to_string(&small).expect("serialize");

        let res = serde_json::from_str::<Public<N_BIG>>(&json);
        assert!(
            res.is_err(),
            "Deserializing into a larger fixed size must error"
        );
    }

    #[test]
    fn public_box_len_mismatch_is_error() {
        const N_SMALL: usize = 8;
        const N_BIG: usize = 12;

        let src = [0xE0u8; N_SMALL];
        let small = PublicBox::<N_SMALL>::new(src);
        let json = serde_json::to_string(&small).expect("serialize");

        let res = serde_json::from_str::<PublicBox<N_BIG>>(&json);
        assert!(
            res.is_err(),
            "Deserializing into a different fixed size must error"
        );
    }
}
