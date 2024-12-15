//! This module provides utilities for decoding length-prefixed messages from I/O streams.
//!
//! Messages are prefixed with an unsigned 64-bit little-endian length header, followed by the
//! message payload. The [`decoder::LengthPrefixDecoder`] is a central component here, maintaining
//! internal buffers and state for partial reads and boundary checks.
//!
//! The module defines errors to handle size mismatches, I/O issues, and boundary violations
//! that may occur during decoding.
//!
//! The abstractions provided in this module enable safe and convenient reading
//! of structured data from streams, including handling unexpected EOFs and ensuring messages
//! fit within allocated buffers.

use std::{borrow::BorrowMut, cmp::min, io};

use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    io::{TryIoErrorKind, TryIoResultKindHintExt},
    result::ensure_or,
};

/// Size in bytes of the message header carrying length information.
/// Currently, HEADER_SIZE is always 8 bytes and encodes a 64-bit little-endian number.
pub const HEADER_SIZE: usize = std::mem::size_of::<u64>();

/// Error enum representing sanity check failures when accessing buffer regions.
///
/// This error is triggered when internal offsets point outside allowable regions.
#[derive(Error, Debug)]
pub enum SanityError {
    /// The given offset exceeded the read buffer bounds.
    #[error("Offset is out of read buffer bounds")]
    OutOfBufferBounds,

    /// The given offset exceeded the message buffer bounds.
    #[error("Offset is out of message buffer bounds")]
    OutOfMessageBounds,
}

/// Error indicating that the message size is larger than the available buffer space.
#[derive(Error, Debug)]
#[error("Message too large ({msg_size} bytes) for buffer ({buf_size} bytes)")]
pub struct MessageTooLargeError {
    msg_size: usize,
    buf_size: usize,
}

impl MessageTooLargeError {
    /// Creates a new `MessageTooLargeError` with the given message and buffer sizes.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rosenpass_util::length_prefix_encoding::decoder::MessageTooLargeError;
    /// let err = MessageTooLargeError::new(1024, 512);
    /// assert_eq!(format!("{}", err), "Message too large (1024 bytes) for buffer (512 bytes)");
    /// ```
    pub fn new(msg_size: usize, buf_size: usize) -> Self {
        Self { msg_size, buf_size }
    }

    /// Ensures the message fits within the given buffer.
    ///
    /// Returns `Ok(())` if `msg_size <= buf_size`, otherwise returns a `MessageTooLargeError`.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rosenpass_util::length_prefix_encoding::decoder::MessageTooLargeError;
    /// let result = MessageTooLargeError::ensure(100, 200);
    /// assert!(result.is_ok());
    ///
    /// let err = MessageTooLargeError::ensure(300, 200).unwrap_err();
    /// assert_eq!(format!("{}", err), "Message too large (300 bytes) for buffer (200 bytes)");
    /// ```
    pub fn ensure(msg_size: usize, buf_size: usize) -> Result<(), Self> {
        let err = MessageTooLargeError { msg_size, buf_size };
        ensure_or(msg_size <= buf_size, err)
    }
}

/// Return type for `ReadFromIo` operations, containing the number of bytes read and an optional message slice.
#[derive(Debug)]
pub struct ReadFromIoReturn<'a> {
    /// Number of bytes read.
    pub bytes_read: usize,
    /// The complete message slice if fully read, otherwise `None`.
    pub message: Option<&'a mut [u8]>,
}

impl<'a> ReadFromIoReturn<'a> {
    /// Creates a new `ReadFromIoReturn`.
    ///
    /// Generally used internally to represent partial or complete read results.
    pub fn new(bytes_read: usize, message: Option<&'a mut [u8]>) -> Self {
        Self {
            bytes_read,
            message,
        }
    }
}

/// An error that may occur when reading from an I/O source.
///
/// This enum wraps I/O errors and message-size errors, allowing higher-level logic to determine
/// if the error is a fundamental I/O problem or a size mismatch issue.
#[derive(Debug, Error)]
pub enum ReadFromIoError {
    /// Error reading from the underlying I/O stream.
    #[error("Error reading from the underlying stream")]
    IoError(#[from] io::Error),

    /// The message size exceeded the capacity of the available buffer.
    #[error("Message size out of buffer bounds")]
    MessageTooLargeError(#[from] MessageTooLargeError),
}

impl TryIoErrorKind for ReadFromIoError {
    fn try_io_error_kind(&self) -> Option<io::ErrorKind> {
        match self {
            ReadFromIoError::IoError(ioe) => Some(ioe.kind()),
            _ => None,
        }
    }
}

/// A decoder for length-prefixed messages.
///
/// This decoder reads a 64-bit little-endian length prefix followed by the message payload.
/// It maintains state so that partial reads from a non-blocking or streaming source can
/// accumulate until a full message is available.
///
/// # Examples
///
/// ```
/// # use std::io::Cursor;
/// # use rosenpass_util::length_prefix_encoding::decoder::LengthPrefixDecoder;
/// let data: Vec<u8> = {
///     let mut buf = Vec::new();
///     buf.extend_from_slice(&(5u64.to_le_bytes())); // message length = 5
///     buf.extend_from_slice(b"hello");
///     buf
/// };
///
/// let mut decoder = LengthPrefixDecoder::new(vec![0; 64]);
/// let mut cursor = Cursor::new(data);
///
/// let message = decoder.read_all_from_stdio(&mut cursor).expect("read failed");
/// assert_eq!(message, b"hello");
/// ```
#[derive(Debug, Default, Clone)]
pub struct LengthPrefixDecoder<Buf: BorrowMut<[u8]>> {
    header: [u8; HEADER_SIZE],
    buf: Buf,
    off: usize,
}

impl<Buf: BorrowMut<[u8]>> LengthPrefixDecoder<Buf> {
    /// Creates a new `LengthPrefixDecoder` with the provided buffer.
    ///
    /// The provided buffer must be large enough to hold the expected maximum message size.
    ///
    /// # Examples
    ///
    /// ```
    /// # use rosenpass_util::length_prefix_encoding::decoder::LengthPrefixDecoder;
    /// let decoder = LengthPrefixDecoder::new(vec![0; 1024]);
    /// assert_eq!(*decoder.bytes_read(), 0);
    /// ```
    pub fn new(buf: Buf) -> Self {
        let header = Default::default();
        let off = 0;
        Self { header, buf, off }
    }

    /// Clears and zeroes all internal state.
    ///
    /// This zeroizes the header and the buffer, as well as resets the offset to zero.
    pub fn clear(&mut self) {
        self.zeroize()
    }

    /// Creates a decoder from parts.
    ///
    /// Typically used for low-level reconstruction of a decoder state.
    pub fn from_parts(header: [u8; HEADER_SIZE], buf: Buf, off: usize) -> Self {
        Self { header, buf, off }
    }

    /// Consumes the decoder and returns its internal parts.
    ///
    /// Returns the header, the underlying buffer, and the current offset.
    pub fn into_parts(self) -> ([u8; HEADER_SIZE], Buf, usize) {
        let Self { header, buf, off } = self;
        (header, buf, off)
    }

    /// Reads a complete message from the given reader.
    ///
    /// Will retry on interrupts and fails if EOF is encountered prematurely. On success,
    /// returns a mutable slice of the fully read message.
    ///
    /// # Examples
    ///
    /// ## Successful read
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::decoder::{LengthPrefixDecoder, ReadFromIoError, MessageTooLargeError};
    /// let mut data: Cursor<Vec<u8>> = {
    ///     let mut buf = Vec::new();
    ///     buf.extend_from_slice(&(3u64.to_le_bytes()));
    ///     // The buffer can also be larger than the message size:
    ///     // Here `cats` is 4 bytes and 1 byte longer than the message size defined in the header
    ///     buf.extend_from_slice(b"cats");
    ///     Cursor::new(buf)
    /// };
    /// let mut decoder = LengthPrefixDecoder::new(vec![0; 8]);
    /// let msg = decoder.read_all_from_stdio(&mut data).expect("read failed");
    /// assert_eq!(msg, b"cat");
    /// ```
    ///
    /// ## MessageTooLargeError
    ///
    /// Buffer of the `LengthPrefixDecoder` configured to be too small:
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::decoder::{LengthPrefixDecoder, ReadFromIoError, MessageTooLargeError};
    /// let mut data: Cursor<Vec<u8>> = {
    ///     let mut buf = Vec::new();
    ///     buf.extend_from_slice(&(7u64.to_le_bytes()));
    ///     buf.extend_from_slice(b"giraffe");
    ///     Cursor::new(buf)
    /// };
    /// // Buffer is too small, should be at least 7 bytes (defined in the header)
    /// let mut decoder = LengthPrefixDecoder::new(vec![0; 5]);
    /// let err = decoder.read_all_from_stdio(&mut data).expect_err("read should have failed");
    /// assert!(matches!(err, ReadFromIoError::MessageTooLargeError(_)));
    /// ```
    ///
    /// ## IOError (EOF)
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::decoder::{LengthPrefixDecoder, ReadFromIoError, MessageTooLargeError};
    /// let mut data: Cursor<Vec<u8>> = {
    ///     let mut buf = Vec::new();
    ///     // Message size set to 10 bytes, but the message is only 7 bytes long
    ///     buf.extend_from_slice(&(10u64.to_le_bytes()));
    ///     buf.extend_from_slice(b"giraffe");
    ///     Cursor::new(buf)
    /// };
    /// let mut decoder = LengthPrefixDecoder::new(vec![0; 10]);
    /// let err = decoder.read_all_from_stdio(&mut data).expect_err("read should have failed");
    /// assert!(matches!(err, ReadFromIoError::IoError(_)));
    /// ```
    pub fn read_all_from_stdio<R: io::Read>(
        &mut self,
        mut r: R,
    ) -> Result<&mut [u8], ReadFromIoError> {
        use io::ErrorKind as K;
        loop {
            match self.read_from_stdio(&mut r).try_io_err_kind_hint() {
                // Success (appeasing the borrow checker by calling message_mut())
                Ok(ReadFromIoReturn {
                    message: Some(_), ..
                }) => break Ok(self.message_mut().unwrap().unwrap()),

                // Unexpected EOF
                Ok(ReadFromIoReturn { bytes_read: 0, .. }) => {
                    break Err(ReadFromIoError::IoError(io::Error::new(
                        K::UnexpectedEof,
                        "",
                    )))
                }

                // Retry
                Ok(ReadFromIoReturn { message: None, .. }) => continue,
                Err((_, Some(K::Interrupted))) => continue,

                // Other error
                Err((e, _)) => break Err(e),
            }
        }
    }

    /// Attempts to read from the given `Read` source into the decoder.
    ///
    /// On success, returns how many bytes were read and a mutable slice of the complete message if fully available.
    ///
    /// # Examples
    ///
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::decoder::{LengthPrefixDecoder, ReadFromIoReturn};
    /// let mut data = Cursor::new([4u64.to_le_bytes().as_slice(), b"cats"].concat());
    /// let mut decoder = LengthPrefixDecoder::new(vec![0; 8]);
    /// decoder.read_from_stdio(&mut data).expect("read failed");
    /// ```
    pub fn read_from_stdio<R: io::Read>(
        &mut self,
        mut r: R,
    ) -> Result<ReadFromIoReturn, ReadFromIoError> {
        Ok(match self.next_slice_to_write_to()? {
            // Read some bytes; any MessageTooLargeError in the call to self.message_mut() is
            // ignored to ensure this function changes no state upon errors; the user should rerun
            // the function and collect the MessageTooLargeError on the following invocation
            Some(buf) => {
                let bytes_read = r.read(buf)?;
                self.advance(bytes_read).unwrap();
                let message = self.message_mut().ok().flatten();
                ReadFromIoReturn {
                    bytes_read,
                    message,
                }
            }
            // Message is already fully read; full delegation to self.message_mut()
            None => ReadFromIoReturn {
                bytes_read: 0,
                message: self.message_mut()?,
            },
        })
    }

    /// Returns the next slice of internal buffer that needs data.
    ///
    /// If the header is not yet fully read, returns the remaining part of the header buffer.
    /// Otherwise, returns the remaining part of the message buffer if the message size is known.
    ///
    /// If no more data is needed (message fully read), returns `Ok(None)`.
    pub fn next_slice_to_write_to(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        fn some_if_nonempty(buf: &mut [u8]) -> Option<&mut [u8]> {
            match buf.is_empty() {
                true => None,
                false => Some(buf),
            }
        }

        macro_rules! return_if_nonempty_some {
            ($opt:expr) => {{
                // Deliberate double expansion of $opt to appease the borrow checker *sigh*
                if $opt.and_then(some_if_nonempty).is_some() {
                    return Ok($opt);
                }
            }};
        }

        return_if_nonempty_some!(Some(self.header_buffer_left_mut()));
        return_if_nonempty_some!(self.message_fragment_left_mut()?);
        Ok(None)
    }

    /// Advances the internal offset by `count` bytes.
    ///
    /// This checks that the offset does not exceed buffer or message limits.
    pub fn advance(&mut self, count: usize) -> Result<(), SanityError> {
        let off = self.off + count;
        let msg_off = off.saturating_sub(HEADER_SIZE);

        use SanityError as E;
        let alloc = self.message_buffer().len();
        let msgsz = self.message_size();
        ensure_or(msg_off <= alloc, E::OutOfBufferBounds)?;
        ensure_or(
            msgsz.map(|s| msg_off <= s).unwrap_or(true),
            E::OutOfMessageBounds,
        )?;

        self.off = off;
        Ok(())
    }

    /// Checks that the allocated message buffer is large enough for the message length.
    ///
    /// If the header is not fully read, this does nothing. If it is, ensures the buffer fits the message.
    pub fn ensure_sufficient_msg_buffer(&self) -> Result<(), MessageTooLargeError> {
        let buf_size = self.message_buffer().len();
        let msg_size = match self.get_header() {
            None => return Ok(()),
            Some(v) => v,
        };
        MessageTooLargeError::ensure(msg_size, buf_size)
    }

    /// Returns a reference to the header buffer.
    pub fn header_buffer(&self) -> &[u8] {
        &self.header[..]
    }

    /// Returns a mutable reference to the header buffer.
    pub fn header_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.header[..]
    }

    /// Returns a reference to the underlying message buffer.
    pub fn message_buffer(&self) -> &[u8] {
        self.buf.borrow()
    }

    /// Returns a mutable reference to the underlying message buffer.
    pub fn message_buffer_mut(&mut self) -> &mut [u8] {
        self.buf.borrow_mut()
    }

    /// Returns a reference to the total number of bytes read so far.
    pub fn bytes_read(&self) -> &usize {
        &self.off
    }

    /// Consumes the decoder and returns the underlying buffer.
    ///
    /// # Examples
    /// ```
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::decoder::{LengthPrefixDecoder, ReadFromIoReturn};
    /// let mut data = Cursor::new([4u64.to_le_bytes().as_slice(), b"cats"].concat());
    /// let mut decoder = LengthPrefixDecoder::new(vec![0; 8]);
    /// decoder.read_all_from_stdio(&mut data).expect("read failed");
    /// let buffer: Vec<u8> = decoder.into_message_buffer();
    /// assert_eq!(buffer, vec![99, 97, 116, 115, 0, 0, 0, 0]);
    /// ```
    pub fn into_message_buffer(self) -> Buf {
        let Self { buf, .. } = self;
        buf
    }

    /// Returns the current offset into the header buffer.
    pub fn header_buffer_offset(&self) -> usize {
        min(self.off, HEADER_SIZE)
    }

    /// Returns the current offset into the message buffer.
    pub fn message_buffer_offset(&self) -> usize {
        self.off.saturating_sub(HEADER_SIZE)
    }

    /// Returns whether the header has been fully read.
    pub fn has_header(&self) -> bool {
        self.header_buffer_offset() == HEADER_SIZE
    }

    /// Returns `true` if the entire message has been read, `false` otherwise.
    pub fn has_message(&self) -> Result<bool, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        let msg_size = match self.get_header() {
            None => return Ok(false),
            Some(v) => v,
        };
        Ok(self.message_buffer_avail().len() == msg_size)
    }

    /// Returns the currently read portion of the header.
    pub fn header_buffer_avail(&self) -> &[u8] {
        let off = self.header_buffer_offset();
        &self.header_buffer()[..off]
    }

    /// Returns a mutable slice of the currently read portion of the header.
    pub fn header_buffer_avail_mut(&mut self) -> &mut [u8] {
        let off = self.header_buffer_offset();
        &mut self.header_buffer_mut()[..off]
    }

    /// Returns the remaining unread portion of the header.
    pub fn header_buffer_left(&self) -> &[u8] {
        let off = self.header_buffer_offset();
        &self.header_buffer()[off..]
    }

    /// Returns a mutable slice of the remaining unread portion of the header.
    pub fn header_buffer_left_mut(&mut self) -> &mut [u8] {
        let off = self.header_buffer_offset();
        &mut self.header_buffer_mut()[off..]
    }

    /// Returns the currently read portion of the message.
    pub fn message_buffer_avail(&self) -> &[u8] {
        let off = self.message_buffer_offset();
        &self.message_buffer()[..off]
    }

    /// Returns a mutable slice of the currently read portion of the message.
    pub fn message_buffer_avail_mut(&mut self) -> &mut [u8] {
        let off = self.message_buffer_offset();
        &mut self.message_buffer_mut()[..off]
    }

    /// Returns the remaining unread portion of the message buffer.
    pub fn message_buffer_left(&self) -> &[u8] {
        let off = self.message_buffer_offset();
        &self.message_buffer()[off..]
    }

    /// Returns a mutable slice of the remaining unread portion of the message buffer.
    pub fn message_buffer_left_mut(&mut self) -> &mut [u8] {
        let off = self.message_buffer_offset();
        &mut self.message_buffer_mut()[off..]
    }

    /// Returns the message size from the header if fully read.
    pub fn get_header(&self) -> Option<usize> {
        match self.header_buffer_offset() == HEADER_SIZE {
            false => None,
            true => Some(u64::from_le_bytes(self.header) as usize),
        }
    }

    /// Returns the message size if known (i.e., if the header is fully read).
    pub fn message_size(&self) -> Option<usize> {
        self.get_header()
    }

    /// Returns the total size of the encoded message (header + payload) if known.
    pub fn encoded_message_bytes(&self) -> Option<usize> {
        self.message_size().map(|sz| sz + HEADER_SIZE)
    }

    /// Returns the complete message fragment if the header is known and buffer is sufficient.
    pub fn message_fragment(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        Ok(self.message_size().map(|sz| &self.message_buffer()[..sz]))
    }

    /// Returns a mutable reference to the complete message fragment.
    pub fn message_fragment_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        Ok(self
            .message_size()
            .map(|sz| &mut self.message_buffer_mut()[..sz]))
    }

    /// Returns the portion of the message fragment that has been filled so far.
    pub fn message_fragment_avail(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment()
            .map(|frag| frag.map(|frag| &frag[..off]))
    }

    /// Returns a mutable portion of the message fragment that has been filled so far.
    pub fn message_fragment_avail_mut(
        &mut self,
    ) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment_mut()
            .map(|frag| frag.map(|frag| &mut frag[..off]))
    }

    /// Returns the remaining portion of the message fragment that still needs to be read.
    pub fn message_fragment_left(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment()
            .map(|frag| frag.map(|frag| &frag[off..]))
    }

    /// Returns a mutable slice of the remaining portion of the message fragment that still needs to be read.
    pub fn message_fragment_left_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment_mut()
            .map(|frag| frag.map(|frag| &mut frag[off..]))
    }

    /// If the entire message is available, returns a reference to it.
    ///
    /// Otherwise returns `Ok(None)`.
    pub fn message(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let sz = self.message_size();
        self.message_fragment_avail()
            .map(|frag_opt| frag_opt.and_then(|frag| (frag.len() == sz?).then_some(frag)))
    }

    /// If the entire message is available, returns a mutable reference to it.
    ///
    /// Otherwise returns `Ok(None)`.
    pub fn message_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let sz = self.message_size();
        self.message_fragment_avail_mut()
            .map(|frag_opt| frag_opt.and_then(|frag| (frag.len() == sz?).then_some(frag)))
    }
}

impl<Buf: BorrowMut<[u8]>> Zeroize for LengthPrefixDecoder<Buf> {
    fn zeroize(&mut self) {
        self.header.zeroize();
        self.message_buffer_mut().zeroize();
        self.off.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_read_from_stdio() {
        use std::io::Cursor;
        let mut data = {
            let mut buf = Vec::new();
            buf.extend_from_slice(&(8u64.to_le_bytes()));
            buf.extend_from_slice(b"cats"); // provide only half of the message
            Cursor::new(buf)
        };

        let mut decoder = LengthPrefixDecoder::new(vec![0; 9]);

        fn loop_read(decoder: &mut LengthPrefixDecoder<Vec<u8>>, data: &mut Cursor<Vec<u8>>) {
            // Read until the buffer is fully read
            let data_len = data.get_ref().len();
            loop {
                let result: ReadFromIoReturn =
                    decoder.read_from_stdio(&mut *data).expect("read failed");
                if data.position() as usize == data_len {
                    // the entire data was read
                    break;
                }
                assert!(result.message.is_none());
                assert!(result.bytes_read > 0); // at least 1 byte was read (or all data was read)
            }
        }

        loop_read(&mut decoder, &mut data);

        // INSERT HERE A TEST FOR EACH INTERNAL METHOD OF LengthPrefixDecoder (decoder)
        assert_eq!(decoder.message_size(), Some(8));

        // Header-related assertions
        assert!(decoder.has_header());
        assert_eq!(decoder.has_message().ok(), Some(false));
        assert_eq!(decoder.header_buffer_offset(), HEADER_SIZE);
        assert_eq!(decoder.header_buffer_avail().len(), HEADER_SIZE);
        assert_eq!(decoder.header_buffer_left().len(), 0);
        {
            let header_buffer_mut: &mut [u8] = decoder.header_buffer_avail_mut();
            assert_eq!(header_buffer_mut, &[8, 0, 0, 0, 0, 0, 0, 0]);
            let header_buffer_ref: &[u8] = decoder.header_buffer_avail();
            assert_eq!(header_buffer_ref, &[8, 0, 0, 0, 0, 0, 0, 0]);
        }
        assert_eq!(decoder.get_header(), Some(8));
        assert_eq!(decoder.message_size(), Some(8));
        assert_eq!(decoder.encoded_message_bytes(), Some(8 + HEADER_SIZE));

        // Message-related assertions
        assert_eq!(*decoder.bytes_read(), 12);
        assert_eq!(decoder.message_buffer_offset(), 4); // "cats" is 4 bytes
        assert_eq!(decoder.message_buffer_avail(), b"cats");
        assert_eq!(decoder.message_buffer_avail_mut(), b"cats");
        assert_eq!(decoder.message_buffer_left().len(), 5); // buffer size is 9, 4 read -> 5 left
        assert_eq!(decoder.message_buffer_left_mut().len(), 5);
        assert!(!decoder.has_message().unwrap()); // not fully read

        // Message fragment assertions
        let frag = decoder.message_fragment().unwrap().unwrap();
        assert_eq!(frag.len(), 8); // full message fragment slice (not fully filled)
        let frag_avail = decoder.message_fragment_avail().unwrap().unwrap();
        assert_eq!(frag_avail, b"cats"); // available portion matches what's read
        let frag_left = decoder.message_fragment_left().unwrap().unwrap();
        assert_eq!(frag_left.len(), 4); // 4 bytes remain to complete the message
        assert_eq!(decoder.message().unwrap(), None); // full message not yet available

        // disassemble the decoder and reassemble it
        let (header, buf, off) = decoder.clone().into_parts();
        let mut decoder = LengthPrefixDecoder::from_parts(header, buf, off);

        let mut data = Cursor::new(Vec::from(b"dogs"));
        loop_read(&mut decoder, &mut data);

        // After providing the remaining "dogs" data, the message should now be fully available.
        assert!(decoder.has_message().unwrap());
        assert_eq!(decoder.message().unwrap().unwrap(), b"catsdogs");

        // At this point:
        // - The entire message (8 bytes) plus the header (8 bytes for the length) should be accounted for.
        assert_eq!(
            decoder.message_fragment_avail().unwrap().unwrap(),
            b"catsdogs"
        );
        assert!(decoder.message_fragment_left().unwrap().unwrap().is_empty());

        // The offsets and buffers should reflect that everything is read.
        assert_eq!(decoder.message_buffer_offset(), 8); // all 8 message bytes are now read
        assert_eq!(decoder.message_buffer_avail(), b"catsdogs");
        assert_eq!(decoder.message_buffer_left().len(), 1); // buffer size was 9, 8 read -> 1 left unused

        // No more data needed to complete the message.
        assert!(decoder.next_slice_to_write_to().unwrap().is_none());

        // clear the decoder
        decoder.clear();
        assert_eq!(decoder.buf, vec![0; 9]);
        assert_eq!(decoder.off, 0);
        assert_eq!(decoder.header, [0; HEADER_SIZE]);
    }
}
