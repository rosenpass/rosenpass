criterion::criterion_main!(keyed_hash::benches, aead::benches, kem::benches);

fn benchid(base: KvPairs, last: KvPairs) -> String {
    format!("{base},{last}")
}

#[derive(Clone, Copy, Debug)]
struct KvPair<'a>(&'a str, &'a str);

impl std::fmt::Display for KvPair<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{k}={v}", k = self.0, v = self.1)
    }
}

#[derive(Clone, Copy, Debug)]
struct KvPairs<'a>(&'a [KvPair<'a>]);

impl std::fmt::Display for KvPairs<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.0.len() {
            0 => Ok(()),
            1 => write!(f, "{}", &self.0[0]),
            _ => {
                let mut delim = "";
                for pair in self.0 {
                    write!(f, "{delim}{pair}")?;
                    delim = ",";
                }
                Ok(())
            }
        }
    }
}

mod kem {
    criterion::criterion_group!(
        benches,
        bench_kyber512_libcrux,
        bench_kyber512_oqs,
        bench_classicmceliece460896_oqs
    );

    use criterion::Criterion;

    fn bench_classicmceliece460896_oqs(c: &mut Criterion) {
        template(
            c,
            "classicmceliece460896",
            "oqs",
            rosenpass_oqs::ClassicMceliece460896,
        );
    }

    fn bench_kyber512_libcrux(c: &mut Criterion) {
        template(
            c,
            "kyber512",
            "libcrux",
            rosenpass_ciphers::subtle::libcrux::kyber512::Kyber512,
        );
    }

    fn bench_kyber512_oqs(c: &mut Criterion) {
        template(c, "kyber512", "oqs", rosenpass_oqs::Kyber512);
    }

    use rosenpass_cipher_traits::primitives::Kem;

    fn template<
        const SK_LEN: usize,
        const PK_LEN: usize,
        const CT_LEN: usize,
        const SHK_LEN: usize,
        T: Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN>,
    >(
        c: &mut Criterion,
        alg_name: &str,
        impl_name: &str,
        scheme: T,
    ) {
        use super::{benchid, KvPair, KvPairs};

        let base = [
            KvPair("primitive", "kem"),
            KvPair("algorithm", alg_name),
            KvPair("implementation", impl_name),
            KvPair("length", "-1"),
        ];

        let kem_benchid = |op| benchid(KvPairs(&base), KvPairs(&[KvPair("operation", op)]));

        c.bench_function(&kem_benchid("keygen"), |bench| {
            let mut sk = [0; SK_LEN];
            let mut pk = [0; PK_LEN];

            bench.iter(|| {
                scheme.keygen(&mut sk, &mut pk).unwrap();
            });
        });

        c.bench_function(&kem_benchid("encaps"), |bench| {
            let mut sk = [0; SK_LEN];
            let mut pk = [0; PK_LEN];
            let mut ct = [0; CT_LEN];
            let mut shk = [0; SHK_LEN];

            scheme.keygen(&mut sk, &mut pk).unwrap();

            bench.iter(|| {
                scheme.encaps(&mut shk, &mut ct, &pk).unwrap();
            });
        });

        c.bench_function(&kem_benchid("decaps"), |bench| {
            let mut sk = [0; SK_LEN];
            let mut pk = [0; PK_LEN];
            let mut ct = [0; CT_LEN];
            let mut shk = [0; SHK_LEN];
            let mut shk2 = [0; SHK_LEN];

            scheme.keygen(&mut sk, &mut pk).unwrap();
            scheme.encaps(&mut shk, &mut ct, &pk).unwrap();

            bench.iter(|| {
                scheme.decaps(&mut shk2, &sk, &ct).unwrap();
            });
        });
    }
}
mod aead {
    criterion::criterion_group!(
        benches,
        bench_chachapoly_libcrux,
        bench_chachapoly_rustcrypto,
        bench_xchachapoly_rustcrypto,
    );

    use criterion::Criterion;

    const KEY_LEN: usize = rosenpass_ciphers::Aead::KEY_LEN;
    const TAG_LEN: usize = rosenpass_ciphers::Aead::TAG_LEN;

    fn bench_xchachapoly_rustcrypto(c: &mut Criterion) {
        template(
            c,
            "xchacha20poly1305",
            "rustcrypto",
            rosenpass_ciphers::subtle::rust_crypto::xchacha20poly1305_ietf::XChaCha20Poly1305,
        );
    }

    fn bench_chachapoly_rustcrypto(c: &mut Criterion) {
        template(
            c,
            "chacha20poly1305",
            "rustcrypto",
            rosenpass_ciphers::subtle::rust_crypto::chacha20poly1305_ietf::ChaCha20Poly1305,
        );
    }

    fn bench_chachapoly_libcrux(c: &mut Criterion) {
        template(
            c,
            "chacha20poly1305",
            "libcrux",
            rosenpass_ciphers::subtle::libcrux::chacha20poly1305_ietf::ChaCha20Poly1305,
        );
    }

    use rosenpass_cipher_traits::primitives::Aead;

    fn template<const NONCE_LEN: usize, T: Aead<KEY_LEN, NONCE_LEN, TAG_LEN>>(
        c: &mut Criterion,
        alg_name: &str,
        impl_name: &str,
        scheme: T,
    ) {
        use crate::{benchid, KvPair, KvPairs};

        let base = [
            KvPair("primitive", "aead"),
            KvPair("algorithm", alg_name),
            KvPair("implementation", impl_name),
        ];
        let aead_benchid = |op, len| {
            benchid(
                KvPairs(&base),
                KvPairs(&[KvPair("operation", op), KvPair("length", len)]),
            )
        };

        let key = [12; KEY_LEN];
        let nonce = [23; NONCE_LEN];
        let ad = [];

        c.bench_function(&aead_benchid("encrypt", "32byte"), |bench| {
            const DATA_LEN: usize = 32;

            let ptxt = [34u8; DATA_LEN];
            let mut ctxt = [0; DATA_LEN + TAG_LEN];

            bench.iter(|| {
                scheme.encrypt(&mut ctxt, &key, &nonce, &ad, &ptxt).unwrap();
            });
        });

        c.bench_function(&aead_benchid("decrypt", "32byte"), |bench| {
            const DATA_LEN: usize = 32;

            let ptxt = [34u8; DATA_LEN];
            let mut ctxt = [0; DATA_LEN + TAG_LEN];
            let mut ptxt_out = [0u8; DATA_LEN];

            scheme.encrypt(&mut ctxt, &key, &nonce, &ad, &ptxt).unwrap();

            bench.iter(|| {
                scheme
                    .decrypt(&mut ptxt_out, &key, &nonce, &ad, &mut ctxt)
                    .unwrap()
            })
        });

        c.bench_function(&aead_benchid("encrypt", "1024byte"), |bench| {
            const DATA_LEN: usize = 1024;

            let ptxt = [34u8; DATA_LEN];
            let mut ctxt = [0; DATA_LEN + TAG_LEN];

            bench.iter(|| {
                scheme.encrypt(&mut ctxt, &key, &nonce, &ad, &ptxt).unwrap();
            });
        });
        c.bench_function(&aead_benchid("decrypt", "1024byte"), |bench| {
            const DATA_LEN: usize = 1024;

            let ptxt = [34u8; DATA_LEN];
            let mut ctxt = [0; DATA_LEN + TAG_LEN];
            let mut ptxt_out = [0u8; DATA_LEN];

            scheme.encrypt(&mut ctxt, &key, &nonce, &ad, &ptxt).unwrap();

            bench.iter(|| {
                scheme
                    .decrypt(&mut ptxt_out, &key, &nonce, &ad, &mut ctxt)
                    .unwrap()
            })
        });
    }
}

mod keyed_hash {
    criterion::criterion_group!(
        benches,
        bench_blake2b_rustcrypto,
        bench_blake2b_libcrux,
        bench_shake256_rustcrypto,
    );

    const KEY_LEN: usize = 32;
    const HASH_LEN: usize = 32;

    use criterion::Criterion;

    fn bench_shake256_rustcrypto(c: &mut Criterion) {
        template(
            c,
            "shake256",
            "rustcrypto",
            &rosenpass_ciphers::subtle::rust_crypto::keyed_shake256::SHAKE256Core,
        );
    }

    fn bench_blake2b_rustcrypto(c: &mut Criterion) {
        template(
            c,
            "blake2b",
            "rustcrypto",
            &rosenpass_ciphers::subtle::rust_crypto::blake2b::Blake2b,
        );
    }

    fn bench_blake2b_libcrux(c: &mut Criterion) {
        template(
            c,
            "blake2b",
            "libcrux",
            &rosenpass_ciphers::subtle::libcrux::blake2b::Blake2b,
        );
    }

    use rosenpass_cipher_traits::primitives::KeyedHash;

    fn template<H: KeyedHash<KEY_LEN, HASH_LEN>>(
        c: &mut Criterion,
        alg_name: &str,
        impl_name: &str,
        _: &H,
    ) where
        H::Error: std::fmt::Debug,
    {
        use crate::{benchid, KvPair, KvPairs};

        let key = [12u8; KEY_LEN];
        let mut out = [0u8; HASH_LEN];

        let base = [
            KvPair("primitive", "keyedhash"),
            KvPair("algorithm", alg_name),
            KvPair("implementation", impl_name),
            KvPair("operation", "hash"),
        ];
        let keyedhash_benchid = |len| benchid(KvPairs(&base), KvPairs(&[KvPair("length", len)]));

        c.bench_function(&keyedhash_benchid("32byte"), |bench| {
            let bytes = [34u8; 32];

            bench.iter(|| {
                H::keyed_hash(&key, &bytes, &mut out).unwrap();
            })
        })
        .bench_function(&keyedhash_benchid("64byte"), |bench| {
            let bytes = [34u8; 64];

            bench.iter(|| {
                H::keyed_hash(&key, &bytes, &mut out).unwrap();
            })
        })
        .bench_function(&keyedhash_benchid("128byte"), |bench| {
            let bytes = [34u8; 128];

            bench.iter(|| {
                H::keyed_hash(&key, &bytes, &mut out).unwrap();
            })
        })
        .bench_function(&keyedhash_benchid("1024byte"), |bench| {
            let bytes = [34u8; 1024];

            bench.iter(|| {
                H::keyed_hash(&key, &bytes, &mut out).unwrap();
            })
        });
    }
}

mod templates {}
