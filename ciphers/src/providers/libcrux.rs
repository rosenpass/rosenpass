//mod blake2;
mod chacha20poly1305;
mod kyber512;

use std::marker::PhantomData;

use crate::providers::basic::BasicProvider;
use rosenpass_cipher_traits::Provider;

#[derive(Debug)]
pub struct LibcruxProvider<FallbackProvider: Provider = BasicProvider>(
    PhantomData<FallbackProvider>,
);

impl<FallbackProvider: Provider> Provider for LibcruxProvider<FallbackProvider> {
    // taken from libcrux:

    type ChaCha20Poly1305 = chacha20poly1305::ChaCha20Poly1305;

    type Kyber512 = kyber512::Kyber512;

    // todo: implement libcrux provider:

    type KeyedBlake2b = FallbackProvider::KeyedBlake2b;

    // taken from basic provider:

    type ClassicMceliece460896 = FallbackProvider::ClassicMceliece460896;

    type XChaCha20Poly1305 = FallbackProvider::XChaCha20Poly1305;
}
