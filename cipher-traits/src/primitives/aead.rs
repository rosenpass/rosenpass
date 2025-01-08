use thiserror::Error;

pub trait Aead<const KEY_LEN: usize, const NONCE_LEN: usize, const TAG_LEN: usize> {
    fn encrypt(
        ciphertext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        plaintext: &[u8],
    ) -> Result<(), Error>;

    fn decrypt(
        plaintext: &mut [u8],
        key: &[u8; KEY_LEN],
        nonce: &[u8; NONCE_LEN],
        ad: &[u8],
        ciphertext: &[u8],
    ) -> Result<(), Error>;
}

#[derive(Debug, Error)]
pub enum Error {
    #[error("internal error")]
    InternalError,
    #[error("decryption error")]
    DecryptError,
}
