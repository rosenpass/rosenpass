use anyhow::Result;
use rosenpass::{
    pqkem::{EphemeralKEM, CCAKEM},
    protocol::{CcaPk, CcaSk, CryptoServer, HandleMsgResult, MsgBuf, PeerPtr, SymKey},
    sodium::sodium_init,
};

use criterion::{black_box, criterion_group, criterion_main, Criterion};

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

fn keygen() -> Result<(CcaSk, CcaPk)> {
    let (mut sk, mut pk) = (CcaSk::zero(), CcaPk::zero());
    CCAKEM::keygen(sk.secret_mut(), pk.secret_mut())?;
    Ok((sk, pk))
}

fn make_server_pair() -> Result<(CryptoServer, CryptoServer)> {
    let psk = SymKey::random();
    let ((ska, pka), (skb, pkb)) = (keygen()?, keygen()?);
    let (mut a, mut b) = (
        CryptoServer::new(ska, pka.clone()),
        CryptoServer::new(skb, pkb.clone()),
    );
    a.add_peer(Some(psk.clone()), pkb)?;
    b.add_peer(Some(psk), pka)?;
    Ok((a, b))
}

fn criterion_benchmark(c: &mut Criterion) {
    sodium_init().unwrap();
    let (mut a, mut b) = make_server_pair().unwrap();
    c.bench_function("cca_secret_alloc", |bench| {
        bench.iter(|| {
            CcaSk::zero();
        })
    });
    c.bench_function("cca_public_alloc", |bench| {
        bench.iter(|| {
            CcaPk::zero();
        })
    });
    c.bench_function("keygen", |bench| {
        bench.iter(|| {
            keygen().unwrap();
        })
    });
    c.bench_function("handshake", |bench| {
        bench.iter(|| {
            hs(black_box(&mut a), black_box(&mut b)).unwrap();
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
