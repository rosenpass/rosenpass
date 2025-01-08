mod blake2;
mod chacha20poly1305;
mod xchacha20poly1305;

use rosenpass_cipher_traits::Provider;

#[derive(Debug)]
pub struct BasicProvider;

impl Provider for BasicProvider {
    type ClassicMceliece460896 = rosenpass_oqs::ClassicMceliece460896;

    type Kyber512 = rosenpass_oqs::Kyber512;

    type KeyedBlake2b = blake2::KeyedBlake2b;

    type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;

    type XChaCha20Poly1305 = xchacha20poly1305::XChaCha20Poly1305;
}
