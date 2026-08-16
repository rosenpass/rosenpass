#![warn(missing_docs)]
#![warn(clippy::missing_docs_in_private_items)]
//! # Rosenpass internal liboqs bindings
//! 
//! provides bindings to `liboqs` C library
//! 
//! This is an internal library; not guarantee is made about its API at this point in time.


/// Call into a libOQS function
macro_rules! oqs_call {
    ($name:path, $($args:expr),*) => {{
        use oqs_sys::common::OQS_STATUS::*;

        match $name($($args),*) {
            OQS_SUCCESS => {}, // nop
            OQS_EXTERNAL_LIB_ERROR_OPENSSL => {
                panic!("OpenSSL error in liboqs' {}.", stringify!($name));
            },
            OQS_ERROR => {
                panic!("Unknown error in liboqs' {}.", stringify!($name));
            }
        }
    }};
    ($name:ident) => { oqs_call!($name, ) };
}

#[macro_use]
mod kem_macro;
oqs_kem!(kyber_512, crate::internal::cipher_traits::algorithms::KemKyber512);
oqs_kem!(
    classic_mceliece_460896,
    crate::internal::cipher_traits::algorithms::KemClassicMceliece460896
);
