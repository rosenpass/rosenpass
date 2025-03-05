use rosenpass_to::{ops::copy_slice, To as _};
use thiserror::Error;

/// Models authenticated encryption with assiciated data (AEAD) functionality.
///
/// The methods of this trait take a `&self` argument as a receiver. This has two reasons:
/// 1. It makes type inference a lot smoother
/// 2. It allows to use the functionality through a trait object or having an enum that has
///    variants for multiple options (like e.g. the `KeyedHash` enum in `rosenpass-ciphers`).
///
/// Since the caller needs an instance of the type to use the functionality, implementors are
/// adviced to implement the [`Default`] trait where possible.
///
/// Example for encrypting a message with a specific [`Aead`] instance:
/// ```
/// use rosenpass_cipher_traits::primitives::Aead;
///
/// const KEY_LEN: usize = 32;
/// const NONCE_LEN: usize = 12;
/// const TAG_LEN: usize = 16;
///
/// fn encrypt_message_given_an_aead<AeadImpl>(
///   aead: &AeadImpl,
///   msg: &str,
///   nonce: &[u8; NONCE_LEN],
///   encrypted: &mut [u8]
/// ) where AeadImpl: Aead<KEY_LEN, NONCE_LEN, TAG_LEN> {
///   let key = [0u8; KEY_LEN]; // This is not a secure key!
///   let ad = b""; // we don't need associated data here
///   aead.encrypt(encrypted, &key, nonce, ad, msg.as_bytes()).unwrap();
/// }
/// ```
///
/// If only the type (but no instance) is available, then we can still encrypt, as long as the type
/// also is [`Default`]:
/// ```
/// use rosenpass_cipher_traits::primitives::Aead;
///
/// const KEY_LEN: usize = 32;
/// const NONCE_LEN: usize = 12;
/// const TAG_LEN: usize = 16;
///
/// fn encrypt_message_without_aead<AeadImpl>(
///   msg: &str,
///   nonce: &[u8; NONCE_LEN],
///   encrypted: &mut [u8]
/// ) where AeadImpl: Default + Aead<KEY_LEN, NONCE_LEN, TAG_LEN> {
///   let key = [0u8; KEY_LEN]; // This is not a secure key!
///   let ad = b""; // we don't need associated data here
///   AeadImpl::default().encrypt(encrypted, &key, nonce, ad, msg.as_bytes()).unwrap();
/// }
/// ```
pub trait Aead<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize> {
    const KEY_LEN: usize = KEY_LEN;
    const NONCE_LEN: usize = NONCE_LEN;
    const TAG_LEN: usize = TAG_LEN;

    /// Encrypts `plaintext` using the given `key` and `nonce`, taking into account the additional
    /// data `ad` and writes the result into `ciphertext`.
    ///
    /// `ciphertext` must be exactly `TAG_LEN` longer than `plaintext`.
    fn encrypt(
        &self,
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), Error>;

    /// Decrypts `ciphertexttext` using the given `key` and `nonce`, taking into account the additional
    /// data `ad` and writes the result into `plaintext`.
    ///
    /// `ciphertext` must be exactly `TAG_LEN` longer than `plaintext`.
    fn decrypt(
        &self,
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), Error>;
}

/// Provides an AEAD API where the nonce is part of the ciphertext.
///
/// The old xaead API had the ciphertext begin with the `nonce`. In order to not having to change
/// the calling code too much, we add a wrapper trait that provides this API and implement it for
/// all AEAD.
pub trait AeadWithNonceInCiphertext<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
>: Aead<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    /// Encrypts `plaintext` using the given `key` and `nonce`, taking into account the additional
    /// data `ad` and writes the result into `ciphertext`.
    ///
    /// `ciphertext` must be exactly `TAG_LEN` + `NONCE_LEN` longer than `plaintext`.
    fn encrypt_with_nonce_in_ctxt(
        &self,
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), Error> {
        // The comparison looks complicated, but we need to do it this way to prevent
        // over/underflows.
        if ciphertext.len() < NONCE_LEN + TAG_LEN
            || ciphertext.len() - TAG_LEN - NONCE_LEN < plaintext.len()
        {
            return Err(Error::InvalidLengths);
        }

        let (n, rest) = ciphertext.split_at_mut(NONCE_LEN);
        copy_slice(nonce).to(n);

        self.encrypt(rest, key, nonce, ad, plaintext)
    }

    /// Decrypts `ciphertexttext` using the given `key` and `nonce`, taking into account the additional
    /// data `ad` and writes the result into `plaintext`.
    ///
    /// `ciphertext` must be exactly `TAG_LEN` + `NONCE_LEN` longer than `plaintext`.
    fn decrypt_with_nonce_in_ctxt(
        &self,
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        // The comparison looks complicated, but we need to do it this way to prevent
        // over/underflows.
        if ciphertext.len() < NONCE_LEN + TAG_LEN
            || ciphertext.len() - TAG_LEN - NONCE_LEN < plaintext.len()
        {
            return Err(Error::InvalidLengths);
        }

        let (nonce, rest) = ciphertext.split_at(NONCE_LEN);
        // We know this should be the right length (we just split it), and everything else would be
        // very unexpected.
        let nonce = nonce.try_into().map_err(|_| Error::InternalError)?;

        self.decrypt(plaintext, key, nonce, ad, rest)
    }
}

impl<
        const KEY_LEN: usize,
        const NONCE_LEN: usize,
        const TAG_LEN: usize,
        T: Aead<KEY_LEN, NONCE_LEN, TAG_LEN>,
    > AeadWithNonceInCiphertext<KEY_LEN, NONCE_LEN, TAG_LEN> for T
{
}

/// The error returned by AEAD operations
#[derive(Debug, Error)]
pub enum Error {
    /// An internal error occurred. This should never be happen and indicates an error in the
    /// AEAD implementation.
    #[error("internal error")]
    InternalError,

    /// Could not decrypt a message because the message is not a valid ciphertext for the given
    /// key.
    #[error("decryption error")]
    DecryptError,

    /// The provided buffers have the wrong lengths.
    #[error("buffers have invalid length")]
    InvalidLengths,
}
