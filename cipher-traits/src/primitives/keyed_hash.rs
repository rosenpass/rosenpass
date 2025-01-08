use thiserror::Error;

pub trait KeyedHash<const K_LEN: usize, const OUT_LEN: usize> {
    fn keyed_hash(k: &[u8; K_LEN], data: &[u8], out: &mut [u8; OUT_LEN]) -> Result<(), Error>;
}

#[derive(Debug, Error)]
#[error("internal error")]
pub struct Error;
