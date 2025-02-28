pub mod keyed_hash;

pub use custom::incorrect_hmac_blake2b;
pub use rust_crypto::{blake2b, keyed_shake256};

pub mod custom;
pub mod rust_crypto;

#[cfg(any(
    feature = "experiment_libcrux_blake2",
    feature = "experiment_libcrux_chachapoly",
    feature = "experiment_libcrux_kyber"
))]
pub mod libcrux;
