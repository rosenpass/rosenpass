//! Traits and implementations for Key Encapsulation Mechanisms (KEMs)
//!
//! KEMs are the interface provided by almost all post-quantum
//! secure key exchange mechanisms.
//!
//! Conceptually KEMs are akin to public-key encryption, but instead of encrypting
//! arbitrary data, KEMs are limited to the transmission of keys, randomly chosen during
//!
//! encapsulation.
//! The [KEM] Trait describes the basic API offered by a Key Encapsulation
//! Mechanism. Two implementations for it are provided, [StaticKEM] and [EphemeralKEM].

/// Key Encapsulation Mechanism
///
/// The KEM interface defines three operations: Key generation, key encapsulation and key
/// decapsulation.
pub trait Kem {
    type Error;

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
    fn keygen(sk: &mut [u8], pk: &mut [u8]) -> Result<(), Self::Error>;

    /// From a public key (`pk`), generate a shared key (`shk`, for local use)
    /// and a cipher text (`ct`, to be sent to the owner of the `pk`).
    ///
    /// `encaps(pk) -> shk, ct`
    fn encaps(shk: &mut [u8], ct: &mut [u8], pk: &[u8]) -> Result<(), Self::Error>;

    /// From a secret key (`sk`) and a cipher text (`ct`) derive a shared key
    /// (`shk`)
    ///
    /// `decaps(sk, ct) -> shk`
    fn decaps(shk: &mut [u8], sk: &[u8], ct: &[u8]) -> Result<(), Self::Error>;
}
