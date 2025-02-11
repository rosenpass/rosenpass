
use assert_tv::tv_if_enabled;

pub struct SecretMomento;
pub struct PublicMomento;
pub struct PublicBoxMomento;

tv_if_enabled! {
    use anyhow::anyhow;
    use assert_tv::{tv_const, TestVectorMomento};
    use base64::Engine;
    use serde_json::Value;
    use rosenpass_secret_memory::{Public, PublicBox, Secret};
    use std::time::{Duration, UNIX_EPOCH};
    use crate::protocol::CookieStore;
    use crate::protocol::CryptoServer;

    impl<const N: usize> TestVectorMomento<Secret<N>> for SecretMomento {

        fn serialize(original_value: &Secret<N>) -> anyhow::Result<serde_json::Value> {
            let encoded = base64::engine::general_purpose::STANDARD.encode(original_value.secret());
            Ok(Value::String(encoded))
        }

        fn deserialize(value: &Value) -> anyhow::Result<Secret<N>> {
            let value: &str = value.as_str().ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
            let decoded = base64::engine::general_purpose::STANDARD.decode(value).map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
            Ok(Secret::<N>::from_slice(decoded.as_slice()))
        }
    }

    impl<const N: usize> TestVectorMomento<PublicBox<N>> for PublicBoxMomento {
        fn serialize(original_value: &PublicBox<N>) -> anyhow::Result<Value> {
            let encoded = base64::engine::general_purpose::STANDARD.encode(original_value.inner.value.as_slice());
            Ok(Value::String(encoded))
        }

        fn deserialize(value: &Value) -> anyhow::Result<PublicBox<N>> {
            let value: &str = value.as_str().ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value.as_bytes()).map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
            let mut trg = Box::new(Public::<N>::zero());
            trg.copy_from_slice(decoded.as_slice());
            let trg = PublicBox {
                inner: trg,
            };
            Ok(trg)
        }
    }

    impl<const N: usize> TestVectorMomento<Public<N>> for PublicMomento {
        fn serialize(original_value: &Public<N>) -> anyhow::Result<serde_json::Value> {
            let encoded = base64::engine::general_purpose::STANDARD.encode(original_value.value.as_slice());
            Ok(Value::String(encoded))
        }
        fn deserialize(value: &Value) -> anyhow::Result<Public<N>> {
            let value: &str = value.as_str().ok_or_else(|| anyhow!("Unexpected value, expected string"))?;
            let decoded = base64::engine::general_purpose::STANDARD
                .decode(value.as_bytes()).map_err(|e| anyhow!("Couldn't decode value: {e}"))?;
            Ok(Public::<N>::from_slice(decoded.as_slice()))
        }
    }

    pub fn de_randomize_time_base_cookie_secrets(cs: &mut CryptoServer, server_name: &'static str) {
        // can't de-randomize values of type Instant (they cannot be serialized / deserialized)
        // We thus don't de-randomize timebase and also not the created_at fields of cookies/biscuits

        // let observed_timebase: u128 = cs.timebase.0.elapsed().as_nanos();
        // let time = UNIX_EPOCH + Duration::from_secs(epoch_seconds);
        // let loaded_timebase: u128 = tv_const!(observed_timebase,
        //     format!("{}-timebase", server_name)
        // );
        // cs.timebase.0 = loaded_timebase.into();

        // cs.cookie_secrets[0].created_at = tv_const!(
        //     cs.cookie_secrets[0].created_at,
        //     {format!("{}-cookie_secret-0-created_at", server_name)}
        // );

        cs.cookie_secrets[0].value = tv_const!(
            cs.cookie_secrets[0].value,
            SecretMomento,
            format!("{}-cookie_secret-0-value", server_name)
        );

        // cs.cookie_secrets[1].created_at = tv_const!(
        //     cs.cookie_secrets[1].created_at,
        //     {format!("{}-cookie_secret-1-created_at", server_name)}
        // );

        cs.cookie_secrets[1].value = tv_const!(
            cs.cookie_secrets[1].value,
            SecretMomento,
            {format!("{}-cookie_secret-1-value", server_name)}
        );

        // cs.biscuit_keys[0].created_at = tv_const!(
        //     cs.biscuit_keys[0].created_at,
        //     {format!("{}-biscuit_key-0-created_at", server_name)}
        // );
        cs.biscuit_keys[0].value = tv_const!(
            cs.biscuit_keys[0].value,
            SecretMomento,
            {format!("{}-biscuit_key-0-value", server_name)}
        );

        // cs.biscuit_keys[1].created_at = tv_const!(
        //     cs.biscuit_keys[1].created_at,
        //     {format!("{}-biscuit_key-1-created_at", server_name)}
        // );
        cs.biscuit_keys[1].value = tv_const!(
            cs.biscuit_keys[1].value,
            SecretMomento,
            format!("{}-biscuit_key-1-value", server_name)
        );
    }


}