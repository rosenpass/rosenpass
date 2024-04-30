use std::path::Path;

pub trait StoreSecret {
    type Error;

    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
}
