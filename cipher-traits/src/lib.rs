mod algorithms;
mod primitives;

pub use algorithms::*;
pub use primitives::*;

pub trait Provider {
    type Kyber512: KemKyber512;
    type ClassicMceliece460896: KemClassicMceliece460896;

    type KeyedBlake2b: KeyedHashBlake2b;

    type ChaCha20Poly1305: AeadChaCha20Poly1305;
    type XChaCha20Poly1305: AeadXChaCha20Poly1305;
}
