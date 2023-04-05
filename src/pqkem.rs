//! This module contains Traits and implementations for Key Encapsulation
//! Mechanisms (KEM). KEMs are the interface provided by almost all post-quantum
//! secure key exchange mechanisms.
//!
//! Conceptually KEMs are akin to public-key encryption, but instead of encrypting
//! arbitrary data, KEMs are limited to the transmission of keys, randomly chosen during
//!
//! encapsulation.
//! The [KEM] Trait describes the basic API offered by a Key Encapsulation
//! Mechanism. Two implementations for it are provided, [SKEM] and [EKEM].

use crate::{RosenpassError, RosenpassMaybeError};

/// Key Encapsulation Mechanism
///
/// The KEM interface defines three operations: Key generation, key encapsulation and key
/// decapsulation.
pub trait KEM {
    /// Secrete Key length
    const SK_LEN: usize;
    /// Public Key length
    const PK_LEN: usize;
    /// Ciphertext length
    const CT_LEN: usize;
    /// Shared Secret length
    const SHK_LEN: usize;

    /// Generate a keypair consisting of secret key (`sk`) and public key (`pk`)
    ///
    /// `keygen() -> sk, pk`
    fn keygen(sk: &mut [u8], pk: &mut [u8]) -> Result<(), RosenpassError>;

    /// From a public key (`pk`), generate a shared key (`shk`, for local use)
    /// and a cipher text (`ct`, to be sent to the owner of the `pk`).
    ///
    /// `encaps(pk) -> shk, ct`
    fn encaps(shk: &mut [u8], ct: &mut [u8], pk: &[u8]) -> Result<(), RosenpassError>;

    /// From a secret key (`sk`) and a cipher text (`ct`) derive a shared key
    /// (`shk`)
    ///
    /// `decaps(sk, ct) -> shk`
    fn decaps(shk: &mut [u8], sk: &[u8], ct: &[u8]) -> Result<(), RosenpassError>;
}

/// A KEM that is secure against Chosen Ciphertext Attacks (CCA).
/// In the context of rosenpass this is used for static keys.
/// Uses [Classic McEliece](https://classic.mceliece.org/) 460896 from liboqs.
///
/// Classic McEliece is chosen because of its high security margin and its small
/// ciphertexts. The public keys are humongous, but (being static keys) the are never transmitted over
/// the wire so this is not a big problem.
pub struct StaticKEM;

/// # Safety
///
/// This Trait impl calls unsafe [oqs_sys] functions, that write to byte
/// slices only identified using raw pointers. It must be ensured that the raw
/// pointers point into byte slices of sufficient length, to avoid UB through
/// overwriting of arbitrary data. This is checked in the following code before
/// the unsafe calls, and an early return with an Err occurs if the byte slice
/// size does not match the required size.
///
/// __Note__: This requirement is stricter than necessary, it would suffice
/// to only check that the buffers are big enough, allowing them to be even
/// bigger. However, from a correctness point of view it does not make sense to
/// allow bigger buffers.
impl KEM for StaticKEM {
    const SK_LEN: usize = oqs_sys::kem::OQS_KEM_classic_mceliece_460896_length_secret_key as usize;
    const PK_LEN: usize = oqs_sys::kem::OQS_KEM_classic_mceliece_460896_length_public_key as usize;
    const CT_LEN: usize = oqs_sys::kem::OQS_KEM_classic_mceliece_460896_length_ciphertext as usize;
    const SHK_LEN: usize =
        oqs_sys::kem::OQS_KEM_classic_mceliece_460896_length_shared_secret as usize;

    fn keygen(sk: &mut [u8], pk: &mut [u8]) -> Result<(), RosenpassError> {
        RosenpassError::check_buffer_size(sk.len(), Self::SK_LEN)?;
        RosenpassError::check_buffer_size(pk.len(), Self::PK_LEN)?;
        unsafe {
            oqs_sys::kem::OQS_KEM_classic_mceliece_460896_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                .to_rg_error()
        }
    }

    fn encaps(shk: &mut [u8], ct: &mut [u8], pk: &[u8]) -> Result<(), RosenpassError> {
        RosenpassError::check_buffer_size(shk.len(), Self::SHK_LEN)?;
        RosenpassError::check_buffer_size(ct.len(), Self::CT_LEN)?;
        RosenpassError::check_buffer_size(pk.len(), Self::PK_LEN)?;
        unsafe {
            oqs_sys::kem::OQS_KEM_classic_mceliece_460896_encaps(
                ct.as_mut_ptr(),
                shk.as_mut_ptr(),
                pk.as_ptr(),
            )
            .to_rg_error()
        }
    }

    fn decaps(shk: &mut [u8], sk: &[u8], ct: &[u8]) -> Result<(), RosenpassError> {
        RosenpassError::check_buffer_size(shk.len(), Self::SHK_LEN)?;
        RosenpassError::check_buffer_size(sk.len(), Self::SK_LEN)?;
        RosenpassError::check_buffer_size(ct.len(), Self::CT_LEN)?;
        unsafe {
            oqs_sys::kem::OQS_KEM_classic_mceliece_460896_decaps(
                shk.as_mut_ptr(),
                ct.as_ptr(),
                sk.as_ptr(),
            )
            .to_rg_error()
        }
    }
}

/// Implements a KEM that is secure against Chosen Plaintext Attacks (CPA).
/// In the context of rosenpass this is used for ephemeral keys.
/// Currently the implementation uses
/// [Kyber 512](https://openquantumsafe.org/liboqs/algorithms/kem/kyber) from liboqs.
///
/// This is being used for ephemeral keys; since these are use-once the first post quantum
/// wireguard paper claimed that CPA security would be sufficient. Nonetheless we choose kyber
/// which provides CCA security since there are no publicly vetted KEMs out there which provide
/// only CPA security.
pub struct EphemeralKEM;

/// # Safety
///
/// This Trait impl calls unsafe [oqs_sys] functions, that write to byte
/// slices only identified using raw pointers. It must be ensured that the raw
/// pointers point into byte slices of sufficient length, to avoid UB through
/// overwriting of arbitrary data. This is checked in the following code before
/// the unsafe calls, and an early return with an Err occurs if the byte slice
/// size does not match the required size.
///
/// __Note__: This requirement is stricter than necessary, it would suffice
/// to only check that the buffers are big enough, allowing them to be even
/// bigger. However, from a correctness point of view it does not make sense to
/// allow bigger buffers.
impl KEM for EphemeralKEM {
    const SK_LEN: usize = oqs_sys::kem::OQS_KEM_kyber_512_length_secret_key as usize;
    const PK_LEN: usize = oqs_sys::kem::OQS_KEM_kyber_512_length_public_key as usize;
    const CT_LEN: usize = oqs_sys::kem::OQS_KEM_kyber_512_length_ciphertext as usize;
    const SHK_LEN: usize = oqs_sys::kem::OQS_KEM_kyber_512_length_shared_secret as usize;
    fn keygen(sk: &mut [u8], pk: &mut [u8]) -> Result<(), RosenpassError> {
        RosenpassError::check_buffer_size(sk.len(), Self::SK_LEN)?;
        RosenpassError::check_buffer_size(pk.len(), Self::PK_LEN)?;
        unsafe {
            oqs_sys::kem::OQS_KEM_kyber_512_keypair(pk.as_mut_ptr(), sk.as_mut_ptr())
                .to_rg_error()
        }
    }
    fn encaps(shk: &mut [u8], ct: &mut [u8], pk: &[u8]) -> Result<(), RosenpassError> {
        RosenpassError::check_buffer_size(shk.len(), Self::SHK_LEN)?;
        RosenpassError::check_buffer_size(ct.len(), Self::CT_LEN)?;
        RosenpassError::check_buffer_size(pk.len(), Self::PK_LEN)?;
        unsafe {
            oqs_sys::kem::OQS_KEM_kyber_512_encaps(
                ct.as_mut_ptr(),
                shk.as_mut_ptr(),
                pk.as_ptr(),
            )
            .to_rg_error()
        }
    }
    fn decaps(shk: &mut [u8], sk: &[u8], ct: &[u8]) -> Result<(), RosenpassError> {
        RosenpassError::check_buffer_size(shk.len(), Self::SHK_LEN)?;
        RosenpassError::check_buffer_size(sk.len(), Self::SK_LEN)?;
        RosenpassError::check_buffer_size(ct.len(), Self::CT_LEN)?;
        unsafe {
            oqs_sys::kem::OQS_KEM_kyber_512_decaps(
                shk.as_mut_ptr(),
                ct.as_ptr(),
                sk.as_ptr(),
            )
            .to_rg_error()
        }
    }
}
