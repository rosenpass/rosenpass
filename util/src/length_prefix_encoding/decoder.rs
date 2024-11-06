use std::{borrow::BorrowMut, cmp::min, io};

use thiserror::Error;
use zeroize::Zeroize;

use crate::{
    io::{TryIoErrorKind, TryIoResultKindHintExt},
    result::ensure_or,
};

/// Size in bytes of a message header carrying length information
pub const HEADER_SIZE: usize = std::mem::size_of::<u64>();

#[derive(Error, Debug)]
/// Error enum to represent various boundary sanity check failures during buffer operations
pub enum SanityError {
    #[error("Offset is out of read buffer bounds")]
    /// Error indicating that the given offset exceeds the bounds of the read buffer
    OutOfBufferBounds,
    #[error("Offset is out of message buffer bounds")]
    /// Error indicating that the given offset exceeds the bounds of the message buffer
    OutOfMessageBounds,
}

#[derive(Error, Debug)]
#[error("Message too large ({msg_size} bytes) for buffer ({buf_size} bytes)")]
/// Error indicating that message exceeds available buffer space
pub struct MessageTooLargeError {
    msg_size: usize,
    buf_size: usize,
}

impl MessageTooLargeError {
    /// Creates a new MessageTooLargeError with the given message and buffer sizes
    pub fn new(msg_size: usize, buf_size: usize) -> Self {
        Self { msg_size, buf_size }
    }

    /// Ensures that the message size fits within the buffer size
    ///
    /// Returns Ok(()) if the message fits, otherwise returns an error with size details
    pub fn ensure(msg_size: usize, buf_size: usize) -> Result<(), Self> {
        let err = MessageTooLargeError { msg_size, buf_size };
        ensure_or(msg_size <= buf_size, err)
    }
}

#[derive(Debug)]
/// Return type for ReadFromIo operations that contains the number of bytes read and an optional message slice
pub struct ReadFromIoReturn<'a> {
    /// Number of bytes read from the input
    pub bytes_read: usize,
    /// Optional slice containing the complete message, if one was read
    pub message: Option<&'a mut [u8]>,
}

impl<'a> ReadFromIoReturn<'a> {
    /// Creates a new ReadFromIoReturn with the given number of bytes read and optional message slice.
    pub fn new(bytes_read: usize, message: Option<&'a mut [u8]>) -> Self {
        Self {
            bytes_read,
            message,
        }
    }
}

#[derive(Debug, Error)]
/// An enum representing errors that can occur during read operations from I/O
pub enum ReadFromIoError {
    /// Error occurred while reading from the underlying I/O stream
    #[error("Error reading from the underlying stream")]
    IoError(#[from] io::Error),
    /// Error occurred because message size exceeded buffer capacity
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

#[derive(Debug, Default, Clone)]
/// A decoder for length-prefixed messages
///
/// This struct provides functionality to decode messages that are prefixed with their length.
/// It maintains internal state for header information, the message buffer, and current offset.
pub struct LengthPrefixDecoder<Buf: BorrowMut<[u8]>> {
    header: [u8; HEADER_SIZE],
    buf: Buf,
    off: usize,
}

impl<Buf: BorrowMut<[u8]>> LengthPrefixDecoder<Buf> {
    /// Creates a new LengthPrefixDecoder with the given buffer
    pub fn new(buf: Buf) -> Self {
        let header = Default::default();
        let off = 0;
        Self { header, buf, off }
    }

    /// Clears and zeroes all internal state
    pub fn clear(&mut self) {
        self.zeroize()
    }

    /// Creates a new LengthPrefixDecoder from its component parts
    pub fn from_parts(header: [u8; HEADER_SIZE], buf: Buf, off: usize) -> Self {
        Self { header, buf, off }
    }

    /// Consumes the decoder and returns its component parts
    pub fn into_parts(self) -> ([u8; HEADER_SIZE], Buf, usize) {
        let Self { header, buf, off } = self;
        (header, buf, off)
    }

    /// Reads a complete message from the given reader into the decoder.
    ///
    /// Retries on interrupts and returns the decoded message buffer on success.
    /// Returns an error if the read fails or encounters an unexpected EOF.
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

    /// Reads from the given reader into the decoder's internal buffers
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

    /// Gets the next buffer slice that can be written to
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

    /// Advances the internal offset by the specified number of bytes
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

    /// Ensures that the internal message buffer is large enough for the message size in the header
    pub fn ensure_sufficient_msg_buffer(&self) -> Result<(), MessageTooLargeError> {
        let buf_size = self.message_buffer().len();
        let msg_size = match self.get_header() {
            None => return Ok(()),
            Some(v) => v,
        };
        MessageTooLargeError::ensure(msg_size, buf_size)
    }

    /// Returns a reference to the header buffer
    pub fn header_buffer(&self) -> &[u8] {
        &self.header[..]
    }

    /// Returns a mutable reference to the header buffer
    pub fn header_buffer_mut(&mut self) -> &mut [u8] {
        &mut self.header[..]
    }

    /// Returns a reference to the message buffer
    pub fn message_buffer(&self) -> &[u8] {
        self.buf.borrow()
    }

    /// Returns a mutable reference to the message buffer
    pub fn message_buffer_mut(&mut self) -> &mut [u8] {
        self.buf.borrow_mut()
    }

    /// Returns the number of bytes read so far
    pub fn bytes_read(&self) -> &usize {
        &self.off
    }

    /// Consumes the decoder and returns just the message buffer
    pub fn into_message_buffer(self) -> Buf {
        let Self { buf, .. } = self;
        buf
    }

    /// Returns the current offset into the header buffer
    pub fn header_buffer_offset(&self) -> usize {
        min(self.off, HEADER_SIZE)
    }

    /// Returns the current offset into the message buffer
    pub fn message_buffer_offset(&self) -> usize {
        self.off.saturating_sub(HEADER_SIZE)
    }

    /// Returns whether a complete header has been read
    pub fn has_header(&self) -> bool {
        self.header_buffer_offset() == HEADER_SIZE
    }

    /// Returns whether a complete message has been read
    pub fn has_message(&self) -> Result<bool, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        let msg_size = match self.get_header() {
            None => return Ok(false),
            Some(v) => v,
        };
        Ok(self.message_buffer_avail().len() == msg_size)
    }

    /// Returns a slice of the available data in the header buffer
    pub fn header_buffer_avail(&self) -> &[u8] {
        let off = self.header_buffer_offset();
        &self.header_buffer()[..off]
    }

    /// Returns a mutable slice of the available data in the header buffer
    pub fn header_buffer_avail_mut(&mut self) -> &mut [u8] {
        let off = self.header_buffer_offset();
        &mut self.header_buffer_mut()[..off]
    }

    /// Returns a slice of the remaining space in the header buffer
    pub fn header_buffer_left(&self) -> &[u8] {
        let off = self.header_buffer_offset();
        &self.header_buffer()[off..]
    }

    /// Returns a mutable slice of the remaining space in the header buffer
    pub fn header_buffer_left_mut(&mut self) -> &mut [u8] {
        let off = self.header_buffer_offset();
        &mut self.header_buffer_mut()[off..]
    }

    /// Returns a slice of the available data in the message buffer
    pub fn message_buffer_avail(&self) -> &[u8] {
        let off = self.message_buffer_offset();
        &self.message_buffer()[..off]
    }

    /// Returns a mutable slice of the available data in the message buffer
    pub fn message_buffer_avail_mut(&mut self) -> &mut [u8] {
        let off = self.message_buffer_offset();
        &mut self.message_buffer_mut()[..off]
    }

    /// Returns a slice of the remaining space in the message buffer
    pub fn message_buffer_left(&self) -> &[u8] {
        let off = self.message_buffer_offset();
        &self.message_buffer()[off..]
    }

    /// Returns a mutable slice of the remaining space in the message buffer
    pub fn message_buffer_left_mut(&mut self) -> &mut [u8] {
        let off = self.message_buffer_offset();
        &mut self.message_buffer_mut()[off..]
    }

    /// Returns the message size from the header if available
    pub fn get_header(&self) -> Option<usize> {
        match self.header_buffer_offset() == HEADER_SIZE {
            false => None,
            true => Some(u64::from_le_bytes(self.header) as usize),
        }
    }

    /// Returns the size of the message if header is available
    pub fn message_size(&self) -> Option<usize> {
        self.get_header()
    }

    /// Returns the total size of the encoded message including header
    pub fn encoded_message_bytes(&self) -> Option<usize> {
        self.message_size().map(|sz| sz + HEADER_SIZE)
    }

    /// Returns a slice of the message fragment if available
    pub fn message_fragment(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        Ok(self.message_size().map(|sz| &self.message_buffer()[..sz]))
    }

    /// Returns a mutable slice of the message fragment if available
    pub fn message_fragment_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        self.ensure_sufficient_msg_buffer()?;
        Ok(self
            .message_size()
            .map(|sz| &mut self.message_buffer_mut()[..sz]))
    }

    /// Returns a slice of the available data in the message fragment
    pub fn message_fragment_avail(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment()
            .map(|frag| frag.map(|frag| &frag[..off]))
    }

    /// Returns a mutable slice of the available data in the message fragment
    pub fn message_fragment_avail_mut(
        &mut self,
    ) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment_mut()
            .map(|frag| frag.map(|frag| &mut frag[..off]))
    }

    /// Returns a slice of the remaining space in the message fragment
    pub fn message_fragment_left(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment()
            .map(|frag| frag.map(|frag| &frag[off..]))
    }

    /// Returns a mutable slice of the remaining space in the message fragment
    pub fn message_fragment_left_mut(&mut self) -> Result<Option<&mut [u8]>, MessageTooLargeError> {
        let off = self.message_buffer_avail().len();
        self.message_fragment_mut()
            .map(|frag| frag.map(|frag| &mut frag[off..]))
    }

    /// Returns a slice of the complete message if available
    pub fn message(&self) -> Result<Option<&[u8]>, MessageTooLargeError> {
        let sz = self.message_size();
        self.message_fragment_avail()
            .map(|frag_opt| frag_opt.and_then(|frag| (frag.len() == sz?).then_some(frag)))
    }

    /// Returns a mutable slice of the complete message if available
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
