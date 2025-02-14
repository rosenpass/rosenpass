pub trait KeyedHash<const KEY_LEN: usize, const HASH_LEN: usize> {
    type Error;
    
    fn keyed_hash(key: &[u8; KEY_LEN], data: &[u8], out: &mut [u8; HASH_LEN]) -> Result<(), Self::Error>;
}

pub trait KeyedHashInstance<const KEY_LEN: usize, const HASH_LEN: usize> {
    type KeyType;
    type OutputType;
    type Error;

    fn keyed_hash(&self, key: &[u8; KEY_LEN], data: &[u8], out: &mut [u8; HASH_LEN]) -> Result<(), Self::Error>;
}