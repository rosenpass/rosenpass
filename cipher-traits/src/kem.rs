//! Traits and implementations for Key Encapsulation Mechanisms (KEMs)
//!
//! KEMs are the interface provided by almost all post-quantum
//! secure key exchange mechanisms.
//!
//! Conceptually KEMs are akin to public-key encryption, but instead of encrypting
//! arbitrary data, KEMs are limited to the transmission of keys, randomly chosen during
//! encapsulation.
//!
//! The [Kem] Trait describes the basic API offered by a Key Encapsulation
//! Mechanism. Two implementations for it are provided, [StaticKEM] and [EphemeralKEM].
//!
//! An example where Alice generates a keypair and gives her public key to Bob, for Bob to
//! encapsulate a symmetric key and Alice to decapsulate it would look as follows.
//! In the example, we are using Kyber512, but any KEM that correctly implements the [Kem]
//! trait could be used as well.
//!```rust
//! use rosenpass_cipher_traits::Kem;
//! use rosenpass_oqs::Kyber512;
//! use rosenpass_secret_memory::Secret;
//!
//! # fn do_doc_test() -> Result<(), Box<dyn std::error::Error>> {
//! type MyKem = Kyber512;
//!
//! let mut alice_sk: Secret<{ MyKem::SK_LEN }> = Secret::zero();
//! let mut alice_pk: [u8; MyKem::PK_LEN] = [0; MyKem::PK_LEN];
//! MyKem::keygen(alice_sk.secret_mut(), &mut alice_pk)?;
//!
//! let mut bob_shk: Secret<{ MyKem::SHK_LEN }> = Secret::zero();
//! let mut bob_ct: [u8; MyKem::CT_LEN] = [0; MyKem::CT_LEN];
//! MyKem::encaps(bob_shk.secret_mut(), &mut bob_ct, &mut alice_pk)?;
//!
//! let mut alice_shk: Secret<{ MyKem::SHK_LEN }> = Secret::zero();
//! MyKem::decaps(alice_shk.secret_mut(), alice_sk.secret_mut(), &mut bob_ct)?;
//!
//! # assert_eq!(alice_shk.secret(), bob_shk.secret());
//! # Ok(())
//! # }
//!```
//!
//! Implementing the [Kem]-trait for a KEM is easy. Mostly, you must format the KEM's
//! keys, and ciphertext as `u8` slices. Below, we provide an example for how the trait can
//! be implemented using a **HORRIBLY INSECURE** DummyKem that only uses static values for keys
//! and ciphertexts as an example.  
//!```rust
//!# use rosenpass_cipher_traits::Kem;
//!
//! struct DummyKem {}
//! impl Kem for DummyKem {
//!
//!     // For this DummyKem, using String for errors is sufficient.
//!     type Error = String;
//!
//!     // For this DummyKem, we will use a single `u8` for everything
//!     const SK_LEN: usize = 1;
//!     const PK_LEN: usize = 1;
//!     const CT_LEN: usize = 1;
//!     const SHK_LEN: usize = 1;
//!
//!     fn keygen(sk: &mut [u8], pk: &mut [u8]) -> Result<(), Self::Error> {
//!         if sk.len() != Self::SK_LEN {
//!             return Err("sk does not have the correct length!".to_string());
//!         }
//!         if pk.len() != Self::PK_LEN {
//!             return Err("pk does not have the correct length!".to_string());
//!         }
//!         sk[0] = 42;
//!         pk[0] = 21;
//!         Ok(())
//!     }
//!
//!     fn encaps(shk: &mut [u8], ct: &mut [u8], pk: &[u8]) -> Result<(), Self::Error> {
//!         if pk.len() != Self::PK_LEN {
//!             return Err("pk does not have the correct length!".to_string());
//!         }
//!         if ct.len() != Self::CT_LEN {
//!             return Err("ct does not have the correct length!".to_string());
//!         }
//!         if shk.len() != Self::SHK_LEN {
//!             return Err("shk does not have the correct length!".to_string());
//!         }
//!         if pk[0] != 21 {
//!             return Err("Invalid public key!".to_string());
//!         }
//!         ct[0] = 7;
//!         shk[0] = 17;
//!         Ok(())
//!     }
//!
//!     fn decaps(shk: &mut [u8], sk: &[u8], ct: &[u8]) -> Result<(), Self::Error> {
//!         if sk.len() != Self::SK_LEN {
//!             return Err("sk does not have the correct length!".to_string());
//!         }
//!         if ct.len() != Self::CT_LEN {
//!             return Err("ct does not have the correct length!".to_string());
//!         }
//!         if shk.len() != Self::SHK_LEN {
//!             return Err("shk does not have the correct length!".to_string());
//!         }
//!         if sk[0] != 42 {
//!             return Err("Invalid public key!".to_string());
//!         }
//!         if ct[0] != 7 {
//!             return Err("Invalid ciphertext!".to_string());
//!         }
//!         shk[0] = 17;
//!         Ok(())
//!     }
//! }
//! # use rosenpass_secret_memory::Secret;
//! #
//! # fn do_doc_test() -> Result<(), Box<dyn std::error::Error>> {
//! # type MyKem = DummyKem;
//! #
//! # let mut alice_sk: Secret<{ MyKem::SK_LEN }> = Secret::zero();
//! # let mut alice_pk: [u8; MyKem::PK_LEN] = [0; MyKem::PK_LEN];
//! # MyKem::keygen(alice_sk.secret_mut(), &mut alice_pk)?;
//!
//! # let mut bob_shk: Secret<{ MyKem::SHK_LEN }> = Secret::zero();
//! # let mut bob_ct: [u8; MyKem::CT_LEN] = [0; MyKem::CT_LEN];
//! # MyKem::encaps(bob_shk.secret_mut(), &mut bob_ct, &mut alice_pk)?;
//! #
//! # let mut alice_shk: Secret<{ MyKem::SHK_LEN }> = Secret::zero();
//! # MyKem::decaps(alice_shk.secret_mut(), alice_sk.secret_mut(), &mut bob_ct)?;
//! #
//! # assert_eq!(alice_shk.secret(), bob_shk.secret());
//! # Ok(())
//! # }
//!```
//!

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
