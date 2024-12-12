//! Objects that implement this Trait provide a way to store their data in way that respects the
//! confidentiality of its data. Specifically, an object implementing this Trait guarantees
//! if its data with [store_secret](StoreSecret::store_secret) are saved in the file with visibility
//! equivalent to [rosenpass_util::file::Visibility::Secret].

use std::path::Path;

/// Objects that implement this Trait provide a standard method to be stored securely. The trait can
/// be implemented as follows for example:
/// # Example
/// ```rust
/// use std::io::Write;
/// use std::path::Path;
/// use rosenpass_secret_memory::file::StoreSecret;
///
/// use rosenpass_util::file::{fopen_w, Visibility};
///
/// struct MyWeirdI32 {
///     _priv_i32: [u8; 4],
/// }
///
/// impl StoreSecret for MyWeirdI32 {
///     type Error = std::io::Error;
///
///     fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
///         fopen_w(path, Visibility::Secret)?.write_all(&self._priv_i32)?;
///         Ok(())
///     }
///
///     fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error> {
///         fopen_w(path, Visibility::Public)?.write_all(&self._priv_i32)?;
///         Ok(())
///     }
/// }
/// ```
pub trait StoreSecret {
    type Error;

    /// Stores the object securely. In particular, it ensures that the visibility is equivalent to
    /// [rosenpass_util::file::Visibility::Secret].
    fn store_secret<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;

    /// Stores the object. No requirement on the visibility is given, but it is common to store
    /// the data with visibility equivalent to [rosenpass_util::file::Visibility::Public].
    fn store<P: AsRef<Path>>(&self, path: P) -> Result<(), Self::Error>;
}
