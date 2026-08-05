use std::path::Path;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};


/// Public key and secret key locations.
#[derive(Debug, Deserialize, Serialize, PartialEq, Eq, Clone)]
#[serde(deny_unknown_fields)]
pub struct Keypair {
    /// path to the public key file
    pub public_key: PathBuf,

    /// path to the secret key file
    pub secret_key: PathBuf,
}

impl Keypair {
    /// Construct a keypair from its fields
    pub fn new<Pk: AsRef<Path>, Sk: AsRef<Path>>(public_key: Pk, secret_key: Sk) -> Self {
        let public_key = public_key.as_ref().to_path_buf();
        let secret_key = secret_key.as_ref().to_path_buf();
        Self {
            public_key,
            secret_key,
        }
    }
}
