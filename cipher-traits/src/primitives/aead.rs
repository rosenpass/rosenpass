use thiserror::Error;

pub trait Aead<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize> {
    const KEY_LEN: usize = KEY_LEN;
    const NONCE_LEN: usize = NONCE_LEN;
    const TAG_LEN: usize = TAG_LEN;

    fn encrypt(
        &self,
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), Error>;

    fn decrypt(
        &self,
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), Error>;
}

/// The API of XChaCha was a bit weird and moved the nonce into the ciphertext. Instead of changing
/// the protocol code, we recreate that API on top of the more normal API, but move it into a
/// separate crate.
pub trait AeadWithNonceInCiphertext<
    const KEY_LEN: usize,
    const NONCE_LEN: usize,
    const TAG_LEN: usize,
>: Aead<KEY_LEN, NONCE_LEN, TAG_LEN>
{
    fn decrypt_with_nonce_in_ctxt(
        &self,
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), Error> {
        if ciphertext.len() < plaintext.len() + TAG_LEN + NONCE_LEN {
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

#[derive(Debug, Error)]
pub enum Error {
    #[error("internal error")]
    InternalError,
    #[error("decryption error")]
    DecryptError,
    #[error("buffers have invalid length")]
    InvalidLengths,
}
