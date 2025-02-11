#![allow(unused_imports)]

use std::ops::DerefMut;
use anyhow::anyhow;
use assert_tv::{tv_const, tv_output};
use assert_tv_macros::test_vec;
use serde_json::{Value};
use rosenpass_secret_memory::policy::*;
use rosenpass_cipher_traits::Kem;
use rosenpass_ciphers::kem::StaticKem;
use rosenpass::{
    protocol::{SSk, SPk, MsgBuf, PeerPtr, CryptoServer, SymKey},
};
use rosenpass::test_vec_integration::{PublicBoxMomento, PublicMomento, SecretMomento};
use rosenpass_secret_memory::{Public, PublicBox, Secret};

#[test_vec(format = "json")]
fn crypto_server_test_vector_1() -> anyhow::Result<()> {
    use rosenpass::test_vec_integration::de_randomize_time_base_cookie_secrets;

    // Set security policy for storing secrets
    secret_policy_try_use_memfd_secrets();

    // initialize secret and public key for peer a ...
    let (peer_a_sk, peer_a_pk) = gen_keypair("a");

    // ... and for peer b
    let (peer_b_sk, peer_b_pk) = gen_keypair("b");

    // initialize server and a pre-shared key
    let psk = tv_const!(SymKey::random(), SecretMomento, "psk", "pre-shared key");
    let mut a = CryptoServer::new(peer_a_sk, peer_a_pk.clone());
    de_randomize_time_base_cookie_secrets(&mut a, "a");

    let mut b = CryptoServer::new(peer_b_sk, peer_b_pk.clone());
    de_randomize_time_base_cookie_secrets(&mut b, "b");

    // introduce peers to each other
    a.add_peer(Some(psk.clone()), peer_b_pk)?;
    b.add_peer(Some(psk), peer_a_pk)?;

    // declare buffers for message exchange
    let (mut a_buf, mut b_buf) = (MsgBuf::zero(), MsgBuf::zero());

    // let a initiate a handshake
    let mut maybe_len = Some(a.initiate_handshake(PeerPtr(0), a_buf.as_mut_slice())?);

    let mut message_index = 0;

    // let a and b communicate
    while let Some(len) = maybe_len {
        tv_output!(a_buf.clone(), PublicMomento, {format!("msg-{}", message_index)});
        message_index += 1;
        maybe_len = b.handle_msg(&a_buf[..len], &mut b_buf[..])?.resp;
        std::mem::swap(&mut a, &mut b);
        std::mem::swap(&mut a_buf, &mut b_buf);
    }

    // all done! Extract the shared keys and ensure they are identical
    let a_key = a.osk(PeerPtr(0))?;
    let b_key = b.osk(PeerPtr(0))?;
    assert_eq!(a_key.secret(), b_key.secret(),
               "the key exchanged failed to establish a shared secret");
    tv_output!(a_key, SecretMomento, "exchanged-key", "final exchanged key");
    Ok(())
 }


fn gen_keypair(peer_name: &'static str,) -> (SSk, SPk) {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem::keygen(sk.secret_mut(), pk.deref_mut()).expect("Error generating keypair");
    let sk: SSk = tv_const!(
        sk,
        SecretMomento,
        format!("{}_sk", peer_name), // name
        format!("{} secret key", peer_name) // description
    );
    let pk: SPk = tv_const!(
        pk,
        PublicBoxMomento,
        format!("{}_pk", peer_name),
        format!("{} public key", peer_name)
    );
    (sk, pk)
}

