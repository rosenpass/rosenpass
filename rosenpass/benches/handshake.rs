use anyhow::Result;
use rosenpass::protocol::{
    CryptoServer, HandleMsgResult, MsgBuf, PeerPtr, ProtocolVersion, SPk, SSk, SymKey,
};
use std::ops::DerefMut;

use rosenpass_cipher_traits::primitives::Kem;
use rosenpass_ciphers::StaticKem;

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use rosenpass_secret_memory::secret_policy_try_use_memfd_secrets;

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

fn keygen() -> Result<(SSk, SPk)> {
    let (mut sk, mut pk) = (SSk::zero(), SPk::zero());
    StaticKem.keygen(sk.secret_mut(), pk.deref_mut())?;
    Ok((sk, pk))
}

fn make_server_pair(protocol_version: ProtocolVersion) -> Result<(CryptoServer, CryptoServer)> {
    let psk = SymKey::random();
    let ((ska, pka), (skb, pkb)) = (keygen()?, keygen()?);
    let (mut a, mut b) = (
        CryptoServer::new(ska, pka.clone()),
        CryptoServer::new(skb, pkb.clone()),
    );
    // TODO: Adapt this to both protocol versions
    a.add_peer(Some(psk.clone()), pkb, protocol_version.clone())?;
    b.add_peer(Some(psk), pka, protocol_version)?;
    Ok((a, b))
}

fn criterion_benchmark_v02(c: &mut Criterion) {
    criterion_benchmark(c, ProtocolVersion::V02)
}

fn criterion_benchmark_v03(c: &mut Criterion) {
    criterion_benchmark(c, ProtocolVersion::V03)
}

fn criterion_benchmark(c: &mut Criterion, protocol_version: ProtocolVersion) {
    secret_policy_try_use_memfd_secrets();
    let (mut a, mut b) = make_server_pair(protocol_version).unwrap();
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

criterion_group!(benches_v02, criterion_benchmark_v02);
criterion_group!(benches_v03, criterion_benchmark_v03);
criterion_main!(benches_v02, benches_v03);
