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
//! Mechanism. Two implementations for it are provided:
//! [Kyber512](../../rosenpass_oqs/kyber_512/enum.Kyber512.html) and
//! [ClassicMceliece460896](../../rosenpass_oqs/classic_mceliece_460896/enum.ClassicMceliece460896.html).
//!
//! An example where Alice generates a keypair and gives her public key to Bob, for Bob to
//! encapsulate a symmetric key and Alice to decapsulate it would look as follows.
//! In the example, we are using Kyber512, but any KEM that correctly implements the [Kem]
//! trait could be used as well.
//!```rust
//! use rosenpass_cipher_traits::Kem;
//! use rosenpass_oqs::Kyber512;
//! # use rosenpass_secret_memory::{secret_policy_use_only_malloc_secrets, Secret};
//!
//! type MyKem = Kyber512;
//! secret_policy_use_only_malloc_secrets();
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
//! # Ok::<(), anyhow::Error>(())
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
//! # use rosenpass_secret_memory::{secret_policy_use_only_malloc_secrets, Secret};
//! #
//! # type MyKem = DummyKem;
//! # secret_policy_use_only_malloc_secrets();
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
//! #
//! # Ok::<(), String>(())
//!```
//!

use thiserror::Error;

/// Key Encapsulation Mechanism
///
/// The KEM interface defines three operations: Key generation, key encapsulation and key
/// decapsulation. The parameters are made available as associated constants for convenience.
///
/// The methods of this trait take a `&self` argument as a receiver. This has two reasons:
/// 1. It makes type inference a lot smoother
/// 2. It allows to use the functionality through a trait object or having an enum that has
///    variants for multiple options (like e.g. the `KeyedHash` enum in `rosenpass-ciphers`).
///
/// Since the caller needs an instance of the type to use the functionality, implementors are
/// adviced to implement the [`Default`] trait where possible.
///
/// Example for encrypting a message with a specific [`Kem`] instance:
/// ```
/// use rosenpass_cipher_traits::primitives::Kem;
///
/// const SK_LEN: usize = 1632;
/// const PK_LEN: usize = 800;
/// const CT_LEN: usize = 768;
/// const SHK_LEN: usize = 32;
///
/// fn encaps_given_a_kem<KemImpl>(
///   kem: &KemImpl,
///   pk: &[u8l PK_LEN],
///   ct: &mut [u8; CT_LEN]
/// ) where KemImpl: Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> -> [u8; SHK_LEN]{
///   let mut shk = [0u8; SHK_LEN];
///   kem.encaps(&mut shk, ct, pk).unwrap();
///   shk
/// }
/// ```
///
/// If only the type (but no instance) is available, then we can still use the trait, as long as
/// the type also is [`Default`]:
/// ```
/// use rosenpass_cipher_traits::primitives::Kem;
///
/// const SK_LEN: usize = 1632;
/// const PK_LEN: usize = 800;
/// const CT_LEN: usize = 768;
/// const SHK_LEN: usize = 32;
///
/// fn encaps_without_kem<KemImpl>(
///   pk: &[u8l PK_LEN],
///   ct: &mut [u8; CT_LEN]
/// ) where KemImpl: Default + Kem<SK_LEN, PK_LEN, CT_LEN, SHK_LEN> -> [u8; SHK_LEN]{
///   let mut shk = [0u8; SHK_LEN];
///   KemImpl::default().encaps(&mut shk, ct, pk).unwrap();
///   shk
/// }
/// ```
pub trait Kem<const SK_LEN: usize, const PK_LEN: usize, const CT_LEN: usize, const SHK_LEN: usize> {
    /// The length of the secret (decapsulation) key.
    const SK_LEN: usize = SK_LEN;

    /// The length of the public (encapsulation) key.
    const PK_LEN: usize = PK_LEN;

    /// The length of the ciphertext.
    const CT_LEN: usize = CT_LEN;

    /// The legnth of the resulting shared key.
    const SHK_LEN: usize = SHK_LEN;

    /// Generate a keypair consisting of secret key (`sk`) and public key (`pk`)
    ///
    /// `keygen() -> sk, pk`
    fn keygen(&self, sk: &mut [u8; SK_LEN], pk: &mut [u8; PK_LEN]) -> Result<(), Error>;

    /// From a public key (`pk`), generate a shared key (`shk`, for local use)
    /// and a cipher text (`ct`, to be sent to the owner of the `pk`).
    ///
    /// `encaps(pk) -> shk, ct`
    fn encaps(
        &self,
        shk: &mut [u8; SHK_LEN],
        ct: &mut [u8; CT_LEN],
        pk: &[u8; PK_LEN],
    ) -> Result<(), Error>;

    /// From a secret key (`sk`) and a cipher text (`ct`) derive a shared key
    /// (`shk`)
    ///
    /// `decaps(sk, ct) -> shk`
    fn decaps(
        &self,
        shk: &mut [u8; SHK_LEN],
        sk: &[u8; SK_LEN],
        ct: &[u8; CT_LEN],
    ) -> Result<(), Error>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("invalid argument")]
    InvalidArgument,
    #[error("internal error")]
    InternalError,
}
