//! Helpers for [tokio::task::LocalKey]

/// Extension trait for [tokio::task::LocalKey]
pub trait LocalKeyExt {
    /// Check whether a tokio LocalKey is set
    fn is_set(&'static self) -> bool;
}

impl<T: 'static> LocalKeyExt for tokio::task::LocalKey<T> {
    fn is_set(&'static self) -> bool {
        self.try_with(|_| ()).is_ok()
    }
}
