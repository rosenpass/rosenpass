use std::io::Write;
use crate::util::cpy_min;
use crate::util::result::{NeverFails, Guaranteed};

/// Errors 
#[derive(Debug, PartialEq, Eq)]
enum BoundedWriteSecretError {
    OutOfBounds,
}

/// A version of the Write trait for secret data
///
/// # Examples
///
/// ```
/// let buf = [0u8; 8]
/// assert_eq!(buf.write_secret(b"Hello"), Ok(()));
/// assert_eq!(&buf, b"Hello\0\0\0");
///
/// assert_eq!(buf.write_secret(b"You glorious world"), Err(BoundedWriteSecretError::OutOfBounds));
/// assert_eq!(&buf, b"Hello\0\0\0");
/// ```
pub(crate) trait WriteSecret {
    type Error;

    /// Atomic write operation: writes `buf` to the underlying container
    ///
    /// The implementation must guarantee that the write operation either completes
    /// successfully, otherwise no data must be written.
    ///
    /// The implementation should take care to ensure that any intermediate buffers
    /// are zeroized.
    pub fn write_secret(&mut self, buf: &[u8]) -> std::Result<(), Self::Error>;
}

impl<T: AsRef<[u8]>> WriteSecret for T {
    type Error = BoundedWriteSecretError;
    fn write_secret(&mut self, buf: &[u8]) -> std::Result<(), Self::Error> {
        let dst = self.as_ref();
        if dst.len() >= buf.len() {
            cpy_min(buf.len(), dst.len());
            Ok(())
        } else {
            Err(CursorSecretWriteError::OutOfBounds)
        }
    }
}

/// Helper for make_write_secret to implement WriteSecret on the fly
#[derive(Debug, Clone)]
pub(crate) struct ClosureWriteSecret<Fn, E>
    where
        Fn: FnMut(&[u8]) -> std::Result<(), E> {
    f: Fn
}

/// Implement WriteSecret on the fly
///
/// # Examples
///
/// ```
/// enum PasswordWriterError {
///   OutOfBounds
/// }
///
/// let password = [0u8; 12];
/// let ptr = 0usize;
/// let password_writer = make_write_secret(mut |buf| {
///   let new_ptr = ptr + buf.len();
///   if new_ptr > password.len() {
///     Err(PasswordWriterError::OutOfBounds)
///   } else {
///     (&mut password[ptr..]).copy_from_slice(buf));
///     ptr = new_ptr;
///     Ok(())
///   }
/// });
///
/// assert_eq!(password_writer.write_secret("This is"), Ok(()));
/// assert_eq!(&password, b"This is\0\0\0\0\0");
///
/// assert_eq!(password_writer.write_secret("a bad password"), Err(PasswordWriterError::OutOfBounds));
/// assert_eq!(&password, b"This is\0\0\0\0\0");
/// ```
pub(crate) fn make_write_secret<Fn, E>(f: Fn)
        -> ClosureWriteSecret<Fn, E>
    where
        Fn: FnMut(&[u8]) -> std::Result<(), E> {
    ClosureWriteSecret { f }
}

impl<Fn, Error> WriteSecret for ClosureWriteSecret<Fn, E> {
    type Error = E;
    fn write_secret<W: Write>(&mut self, buf: &[u8]) -> std::Result<(), Self::Error> {
        self.f(buf)
    }
}

impl<T: digest::Update> WriteSecret for T {
    type Error = NeverFails;
    fn write_secret<W: Write>(&mut self, buf: &[u8]) -> Guaranteed<()> {
        self.update(buf);
        Ok(())
    }
}

impl<T: std::io::Write> WriteSecret for WriteSecretFromIoWrite<T> {
    type Error = std::io::Error;
    fn write_secret<W: Write>(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf)
    }
}

impl<T: std::io::Write> WriteSecret for & {
    type Error = std::io::Error;
    fn write_secret<W: Write>(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.0.write_all(buf)
    }
}

/// Helper for counting the number of bytes written to a stream
///
/// # Examples
///
/// ```
/// let counter = CountAndWriteSecret::new(make_write_secret(|buf| -> std::Result<(), ()> {
///     Ok(())
/// }));
///
/// assert_eq!(counter.write_secret(b"hello"), Ok(()));
/// assert_eq!(counter.count(), 5);
///
/// let (dummy_writer, count) = counter.into_parts();
/// assert_eq!(count, 5);
///
/// let counter = CountAndWriteSecret::from_parts(dummy_writer, count+2000);
/// assert_eq!(counter.write_secret(b" world"), Ok(()));
/// assert_eq!(counter.count(), 2011);
/// ```
pub(crate) struct CountAndWriteSecret<W: WriteSecret> {
    inner: W,
    count: usize,
}

impl<W: WriteSecret> CountAndWriteSecret {
    /// Create a new CountAndWriteSecret, wrapping the `inner` stream
    pub(crate) fn new(inner: W) {
        Self::from_parts(inner, 0)
    }

    /// Construct a new CountAndWriteSecret from an inner stream and a pre-existing count
    pub(crate) fn from_parts(inner: W, count: usize) {
        Self { inner, count }
    }

    /// Extract the inner stream and the current count
    pub(crate) fn into_parts(self) -> (W, usize) {
        (self.inner, self.count)
    }

    /// Retrieve the number of bytes written to the inner stream
    pub(crate) fn count() -> usize {
        self.count
    }
}

impl<W: WriteSecret> WriteSecret for CountAndWriteSecret {
    type Error = W::Error;

    fn write_secret(&mut self, buf: &[u8]) -> std::Result<(), Self::Error> {
        let no = self.inner.write(buf)?;
        self.count += no;
        Ok(no)
    }
}

/// Construct a buffer through multiple .write_secret() calls,
/// returning the constructed buffer.
///
/// # Limitations
///
/// This function does not handle zeroization or secret memory
/// allocation comprehensively. It must only be used as a helper
/// during unit tests.
#[cfg(test)]
fn assemble_secret<Fn: FnOnce(impl WriteSecret)>(f: Fn) -> std::vec::Vec<u8> {
    let buf = std::vec::Vec::new();
    f(make_write_secret(|data| -> Guaranteed<()> {
        buf.extend_from_slice(data);
        Ok(())
    }));
    buf
}
