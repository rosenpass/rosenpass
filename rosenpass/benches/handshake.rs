use rand::{thread_rng, RngCore};
use rosenpass::protocol::{
    CryptoServer, EPk, ESk, HandleMsgResult, MsgBuf, PeerPtr, SPk, SSk, SymKey,
};
use rosenpass_cipher_traits::{
    aead_chacha20poly1305,
    kem_kyber512::{CT_LEN, SHK_LEN},
    AeadChaCha20Poly1305, Kem, KemKyber512, Provider,
};
use rosenpass_secret_memory::secret_policy_try_use_memfd_secrets;

use rosenpass_ciphers::providers::basic::BasicProvider;
#[cfg(feature = "libcrux_experiment")]
use rosenpass_ciphers::providers::libcrux::LibcruxProvider;

use anyhow::Result;
use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};

use std::ops::DerefMut as _;

fn handle(
    tx: &mut CryptoServer,
    msgb: &mut MsgBuf,
    msgl: usize,
    rx: &mut CryptoServer,
    resb: &mut MsgBuf,
) -> Result<(Option<SymKey>, Option<SymKey>)> {
    let HandleMsgResult {
        exchanged_with: xch,
        resp,
    } = rx.handle_msg(&msgb[..msgl], &mut **resb)?;
    assert!(matches!(xch, None | Some(PeerPtr(0))));

    let xch = xch.map(|p| rx.osk(p).unwrap());
    let (rxk, txk) = resp
        .map(|resl| handle(rx, resb, resl, tx, msgb))
        .transpose()?
        .unwrap_or((None, None));

    assert!(rxk.is_none() || xch.is_none());
    Ok((txk, rxk.or(xch)))
}

fn hs(ini: &mut CryptoServer, res: &mut CryptoServer) -> Result<()> {
    let (mut inib, mut resb) = (MsgBuf::zero(), MsgBuf::zero());
    let sz = ini.initiate_handshake(PeerPtr(0), &mut *inib)?;
    let (kini, kres) = handle(ini, &mut inib, sz, res, &mut resb)?;
    assert!(kini.unwrap().secret() == kres.unwrap().secret());
    Ok(())
}

fn static_keygen() -> Result<(SSk, SPk)> {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    <BasicProvider as Provider>::ClassicMceliece460896::keygen(sk.secret_mut(), pk.deref_mut())?;
    Ok((sk, pk))
}

fn bench_providers(c: &mut Criterion, path: &str) {
    bench_provider::<BasicProvider>(c, &format!("{path}_basic"));
    #[cfg(feature = "experiment_libcrux")]
    bench_provider::<LibcruxProvider>(c, &format!("{path}_libcrux"));
}

fn bench_provider<P: Provider>(c: &mut Criterion, path: &str) {
    bench_kyber512::<P::Kyber512>(c, &format!("{path}_kyber512"));
    bench_chacha20poly1305::<P::ChaCha20Poly1305>(c, &format!("{path}_chacha20poly1305"));
}

fn bench_kyber512<Kem: KemKyber512>(c: &mut Criterion, path: &str) {
    c.bench_function(&format!("{path}_keygen"), bench_kyber512_keygen::<Kem>);

    c.bench_function(&format!("{path}_encaps"), bench_kyber512_encaps::<Kem>);

    c.bench_function(&format!("{path}_decaps"), bench_kyber512_decaps::<Kem>);
}

fn bench_chacha20poly1305<Aead: AeadChaCha20Poly1305>(c: &mut Criterion, path: &str) {
    c.bench_function(
        &format!("{path}_encrypt-128-bytes"),
        bench_chacha20poly1305_encrypt_128_bytes::<Aead>,
    );
    c.bench_function(
        &format!("{path}_decrypt-128-bytes"),
        bench_chacha20poly1305_decrypt_128_bytes::<Aead>,
    );
}

fn bench_chacha20poly1305_encrypt_128_bytes<Aead: AeadChaCha20Poly1305>(bench: &mut Bencher) {
    let mut key = [0u8; aead_chacha20poly1305::KEY_LEN];
    let mut nonce = [0u8; aead_chacha20poly1305::NONCE_LEN];

    thread_rng().fill_bytes(&mut key);
    thread_rng().fill_bytes(&mut nonce);

    let ad = [0u8; 16];
    let plaintext = [0u8; 128];
    let mut ciphertext = [0u8; 128 + 16];
    bench.iter(|| Aead::encrypt(&mut ciphertext, &key, &nonce, &ad, &plaintext))
}

fn bench_chacha20poly1305_decrypt_128_bytes<Aead: AeadChaCha20Poly1305>(bench: &mut Bencher) {
    let mut key = [0u8; aead_chacha20poly1305::KEY_LEN];
    let mut nonce = [0u8; aead_chacha20poly1305::NONCE_LEN];

    thread_rng().fill_bytes(&mut key);
    thread_rng().fill_bytes(&mut nonce);

    let ad = [0u8; 16];
    let mut plaintext = [0u8; 128];
    let mut ciphertext = [0u8; 128 + 16];
    Aead::encrypt(&mut ciphertext, &key, &nonce, &ad, &plaintext).unwrap();

    bench.iter(|| Aead::decrypt(&mut plaintext, &key, &nonce, &ad, &ciphertext))
}

fn bench_kyber512_keygen<Kem: KemKyber512>(bench: &mut Bencher) {
    let (mut sk, mut pk) = (ESk::zero(), EPk::zero());
    bench.iter(|| {
        Kem::keygen(sk.secret_mut(), &mut pk).unwrap();
    })
}

fn bench_kyber512_encaps<Kem: KemKyber512>(bench: &mut Bencher) {
    let (mut sk, mut pk) = (ESk::zero(), EPk::zero());
    let mut shk = [0u8; SHK_LEN];
    let mut ct = [0u8; CT_LEN];

    Kem::keygen(sk.secret_mut(), &mut pk).unwrap();
    bench.iter(|| Kem::encaps(&mut shk, &mut ct, &pk))
}

fn bench_kyber512_decaps<Kem: KemKyber512>(bench: &mut Bencher) {
    let (mut sk, mut pk) = (ESk::zero(), EPk::zero());
    let mut shk = [0u8; SHK_LEN];
    let mut ct = [0u8; CT_LEN];

    Kem::keygen(sk.secret_mut(), &mut pk).unwrap();
    Kem::encaps(&mut shk, &mut ct, &pk).unwrap();
    bench.iter(|| Kem::decaps(&mut shk, sk.secret(), &ct))
}

fn make_server_pair() -> Result<(CryptoServer, CryptoServer)> {
    let psk = SymKey::random();
    let ((ska, pka), (skb, pkb)) = (static_keygen()?, static_keygen()?);
    let (mut a, mut b) = (
        CryptoServer::new(ska, pka.clone()),
        CryptoServer::new(skb, pkb.clone()),
    );
    a.add_peer(Some(psk.clone()), pkb)?;
    b.add_peer(Some(psk), pka)?;
    Ok((a, b))
}

fn criterion_benchmark(c: &mut Criterion) {
    secret_policy_try_use_memfd_secrets();
    let (mut a, mut b) = make_server_pair().unwrap();
    c.bench_function("cca_secret_alloc", |bench| {
        bench.iter(|| {
            SSk::zero();
        })
    });
    c.bench_function("cca_public_alloc", |bench| {
        bench.iter(|| {
            SPk::zero();
        })
    });
    c.bench_function("static_keygen", |bench| {
        bench.iter(|| {
            static_keygen().unwrap();
        })
    });

    bench_providers(c, "crypto-providers");

    c.bench_function("handshake", |bench| {
        bench.iter(|| {
            hs(black_box(&mut a), black_box(&mut b)).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
