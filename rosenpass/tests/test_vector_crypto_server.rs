//! # Deterministic protocol test based on captured internal randomness
//!
//! This test validates the rosenpass protocol implementation by recording all internal randomness
//! during execution and saving it to a test vector file (`crypto_server_test_vector_1.toml`).
//! On subsequent runs, the test replays this randomness to enforce deterministic behavior,
//! making any changes to the protocol's internal logic observable through test failures.
//!
//! ## Reinitializing the Test Vector
//!
//! If the test fails due to a mismatch between current output and the recorded test vector,
//! it likely indicates a change in implementation. To accept and re-record the new behavior,
//! re-run the test in initialization mode by setting the environment variable:
//!
//! ```bash
//! TEST_MODE=init cargo test crypto_server_test_vector_1
//! ```

use assert_tv::{test_vec_case, TestValue, TestVector, TestVectorActive, TestVectorSet};
use rosenpass::protocol::basic_types::{MsgBuf, SPk, SSk, SymKey};
use rosenpass::protocol::osk_domain_separator::OskDomainSeparator;
use rosenpass::protocol::test_vector_sets::deserialize_byte_vec;
use rosenpass::protocol::test_vector_sets::serialize_byte_vec;
use rosenpass::protocol::{CryptoServer, PeerPtr, ProtocolVersion};
use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;
use rosenpass_secret_memory::policy::*;
use rosenpass_secret_memory::{PublicBox, Secret};
use std::ops::DerefMut;

use rosenpass::protocol::constants::COOKIE_SECRET_LEN;
use rosenpass_ciphers::KEY_LEN;

#[derive(TestVectorSet)]
pub struct TestCaseValues {
    #[test_vec(name = "peer_a_sk")]
    #[test_vec(description = "test setup: peer a secret key")]
    #[test_vec(offload = true)]
    peer_a_sk: TestValue<Secret<{ StaticKem::SK_LEN }>>,
    #[test_vec(name = "peer_a_pk")]
    #[test_vec(description = "test setup: peer a public key")]
    #[test_vec(offload = true)]
    peer_a_pk: TestValue<PublicBox<{ StaticKem::PK_LEN }>>,

    #[test_vec(name = "peer_b_sk")]
    #[test_vec(description = "test setup: peer b secret key")]
    #[test_vec(offload = true)]
    peer_b_sk: TestValue<Secret<{ StaticKem::SK_LEN }>>,
    #[test_vec(name = "peer_b_pk")]
    #[test_vec(description = "test setup: peer b public key")]
    #[test_vec(offload = true)]
    peer_b_pk: TestValue<PublicBox<{ StaticKem::PK_LEN }>>,

    #[test_vec(name = "psk")]
    #[test_vec(description = "pre-shared key")]
    psk: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "message")]
    #[test_vec(description = "message exchanged by the protocol parties")]
    #[test_vec(serialize_with = "serialize_byte_vec")]
    #[test_vec(deserialize_with = "deserialize_byte_vec")]
    #[test_vec(offload = true)]
    message: TestValue<Vec<u8>>,

    #[test_vec(name = "exchanged_key")]
    #[test_vec(description = "final exchanged key")]
    exchanged_key: TestValue<Secret<KEY_LEN>>,
}

#[derive(TestVectorSet)]
struct CryptoServerTestValues {
    #[test_vec(name = "CryptoServer::cookie_secrets[0]")]
    cookie_secret_0: TestValue<Secret<COOKIE_SECRET_LEN>>,

    #[test_vec(name = "CryptoServer::cookie_secrets[1]")]
    cookie_secret_1: TestValue<Secret<COOKIE_SECRET_LEN>>,

    #[test_vec(name = "CryptoServer::biscuit_keys[0]")]
    biscuit_key_0: TestValue<Secret<KEY_LEN>>,

    #[test_vec(name = "CryptoServer::biscuit_keys[1]")]
    biscuit_key_1: TestValue<Secret<KEY_LEN>>,
}

#[test_vec_case(format = "toml")]
fn crypto_server_test_vector_1() -> anyhow::Result<()> {
    type TV = TestVectorActive;
    let test_values: TestCaseValues = TV::initialize_values();

    // Set security policy for storing secrets
    secret_policy_try_use_memfd_secrets();

    // initialize secret and public key for peer a ...
    let (mut peer_a_sk, mut peer_a_pk) = gen_keypair::<TV>();

    TV::expose_mut_value(&test_values.peer_a_sk, &mut peer_a_sk);
    TV::expose_mut_value(&test_values.peer_a_pk, &mut peer_a_pk);

    // ... and for peer b
    let (mut peer_b_sk, mut peer_b_pk) = gen_keypair::<TV>();

    TV::expose_mut_value(&test_values.peer_b_sk, &mut peer_b_sk);
    TV::expose_mut_value(&test_values.peer_b_pk, &mut peer_b_pk);

    // initialize server and a pre-shared key
    let psk = TV::expose_value(&test_values.psk, SymKey::random());

    let mut a = CryptoServer::new(peer_a_sk, peer_a_pk.clone());
    de_randomize_time_base_cookie_secrets::<TV>(&mut a);

    let mut b = CryptoServer::new(peer_b_sk, peer_b_pk.clone());
    de_randomize_time_base_cookie_secrets::<TV>(&mut b);

    // introduce peers to each other
    a.add_peer(
        Some(psk.clone()),
        peer_b_pk,
        ProtocolVersion::V03,
        OskDomainSeparator::default(),
    )?;
    b.add_peer(
        Some(psk),
        peer_a_pk,
        ProtocolVersion::V03,
        OskDomainSeparator::default(),
    )?;

    // declare buffers for message exchange
    let (mut a_buf, mut b_buf) = (MsgBuf::zero(), MsgBuf::zero());

    // let a initiate a handshake
    let mut maybe_len =
        Some(a.initiate_handshake_with_test_vector::<TV>(PeerPtr(0), a_buf.as_mut_slice())?);

    // let a and b communicate
    while let Some(len) = maybe_len {
        TV::check_value(&test_values.message, &a_buf[..len].to_vec());
        maybe_len = b
            .handle_msg_with_test_vector::<TV>(&a_buf[..len], &mut b_buf[..])?
            .resp;
        std::mem::swap(&mut a, &mut b);
        std::mem::swap(&mut a_buf, &mut b_buf);
    }

    // all done! Extract the shared keys and ensure they are identical
    let a_key = a.osk(PeerPtr(0))?;
    let b_key = b.osk(PeerPtr(0))?;
    assert_eq!(
        a_key.secret(),
        b_key.secret(),
        "the key exchanged failed to establish a shared secret"
    );

    TV::check_value(&test_values.exchanged_key, &a_key);
    Ok(())
}
fn gen_keypair<TV: TestVector>() -> (SSk, SPk) {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem
        .keygen(sk.secret_mut(), pk.deref_mut())
        .expect("Error generating keypair");
    (sk, pk)
}

pub fn de_randomize_time_base_cookie_secrets<TV: TestVector>(cs: &mut CryptoServer) {
    let test_values: CryptoServerTestValues = TV::initialize_values();

    TV::expose_mut_value(
        &test_values.cookie_secret_0,
        &mut cs.cookie_secrets[0].value,
    );

    TV::expose_mut_value(
        &test_values.cookie_secret_1,
        &mut cs.cookie_secrets[1].value,
    );

    TV::expose_mut_value(&test_values.biscuit_key_0, &mut cs.biscuit_keys[0].value);

    TV::expose_mut_value(&test_values.biscuit_key_1, &mut cs.biscuit_keys[1].value);
}
