//! Utilities for encoding length-prefixed messages that can be transmitted via I/O streams.
//!
//! Messages are prefixed with an unsigned 64-bit little-endian length header, followed by the
//! message payload. Each [`LengthPrefixEncoder`] maintains internal buffers and additional state for as-yet
//! incomplete messages.
//!
//! It also performs sanity checks and handles typical error conditions that may be encountered
//! when writing structured data to an output sink (such as stdout or an active socket connection).

use std::{
    borrow::{Borrow, BorrowMut},
    cmp::min,
    io,
};

use thiserror::Error;
use zeroize::Zeroize;

use crate::{io::IoResultKindHintExt, result::ensure_or};

/// Size in bytes of the message header carrying length information.
/// Currently, HEADER_SIZE is always 8 bytes and encodes a 64-bit little-endian number.
pub const HEADER_SIZE: usize = std::mem::size_of::<u64>();

#[derive(Error, Debug, Clone, Copy)]
#[error("Write position is out of buffer bounds")]
/// Error indicating that the given offset exceeds the bounds of the allocated buffer.
pub struct PositionOutOfBufferBounds;

#[derive(Error, Debug, Clone, Copy)]
#[error("Write position is out of message bounds")]
/// Error indicating that the given offset exceeds the bounds of the message.
pub struct PositionOutOfMessageBounds;

#[derive(Error, Debug, Clone, Copy)]
#[error("Write position is out of header bounds")]
/// Error indicating that the given offset exceeds the bounds of the header.
pub struct PositionOutOfHeaderBounds;

#[derive(Error, Debug, Clone, Copy)]
#[error("Message length is bigger than buffer length")]
/// Error indicating that the message size is larger than the available buffer space.
pub struct MessageTooLarge;

#[derive(Error, Debug, Clone, Copy)]
/// Error enum representing sanity check failures related to the message size.
pub enum MessageLenSanityError {
    /// Error indicating position is beyond message boundaries
    #[error("{0:?}")]
    PositionOutOfMessageBounds(#[from] PositionOutOfMessageBounds),
    /// Error indicating message length exceeds buffer capacity
    #[error("{0:?}")]
    MessageTooLarge(#[from] MessageTooLarge),
}

#[derive(Error, Debug, Clone, Copy)]
/// Error enum representing sanity check failures related to out-of-bounds memory access.
pub enum PositionSanityError {
    /// Error indicating position is beyond message boundaries
    #[error("{0:?}")]
    PositionOutOfMessageBounds(#[from] PositionOutOfMessageBounds),
    /// Error indicating position is beyond buffer boundaries
    #[error("{0:?}")]
    PositionOutOfBufferBounds(#[from] PositionOutOfBufferBounds),
}

#[derive(Error, Debug, Clone, Copy)]
/// Error enum representing sanity check failures of any kind.
pub enum SanityError {
    /// Error indicating position is beyond message boundaries
    #[error("{0:?}")]
    PositionOutOfMessageBounds(#[from] PositionOutOfMessageBounds),
    /// Error indicating position is beyond buffer boundaries
    #[error("{0:?}")]
    PositionOutOfBufferBounds(#[from] PositionOutOfBufferBounds),
    /// Error indicating message length exceeds buffer capacity
    #[error("{0:?}")]
    MessageTooLarge(#[from] MessageTooLarge),
}

impl TryFrom<SanityError> for MessageLenSanityError {
    type Error = PositionOutOfBufferBounds;

    fn try_from(value: SanityError) -> Result<Self, Self::Error> {
        use {MessageLenSanityError as T, SanityError as F};
        match value {
            F::PositionOutOfMessageBounds(e) => Ok(T::PositionOutOfMessageBounds(e)),
            F::MessageTooLarge(e) => Ok(T::MessageTooLarge(e)),
            F::PositionOutOfBufferBounds(e) => Err(e),
        }
    }
}

impl From<MessageLenSanityError> for SanityError {
    fn from(value: MessageLenSanityError) -> Self {
        use {MessageLenSanityError as F, SanityError as T};
        match value {
            F::PositionOutOfMessageBounds(e) => T::PositionOutOfMessageBounds(e),
            F::MessageTooLarge(e) => T::MessageTooLarge(e),
        }
    }
}

impl From<PositionSanityError> for SanityError {
    fn from(value: PositionSanityError) -> Self {
        use {PositionSanityError as F, SanityError as T};
        match value {
            F::PositionOutOfBufferBounds(e) => T::PositionOutOfBufferBounds(e),
            F::PositionOutOfMessageBounds(e) => T::PositionOutOfMessageBounds(e),
        }
    }
}

/// Return type for `WriteToIo` operations, containing the number of bytes written and a completion flag.
pub struct WriteToIoReturn {
    /// Number of bytes successfully written in this operation
    pub bytes_written: usize,
    /// Whether the write operation has completed fully
    pub done: bool,
}

#[derive(Clone, Copy, Debug)]
/// An encoder for length-prefixed messages.
///
/// # Examples
///
///  ## Writing to output streams
///
/// Simplified usage example:
///
/// ```rust
/// use rosenpass_util::length_prefix_encoding::encoder::LengthPrefixEncoder;
/// use rosenpass_util::length_prefix_encoding::encoder::HEADER_SIZE;
///
/// let message = String::from("hello world");
/// let mut encoder = LengthPrefixEncoder::from_message(message.as_bytes());
///
/// let mut output = Vec::new();
/// encoder.write_all_to_stdio(&mut output).expect("failed to write_all");
///
/// assert_eq!(output.len(), message.len() + HEADER_SIZE);
///
/// let (header, body) = output.split_at(HEADER_SIZE);
/// let length = u64::from_le_bytes(header.try_into().unwrap());
///
/// assert_eq!(length as usize, message.len());
/// assert_eq!(body, message.as_bytes());
/// ```
///
/// For more examples, see also:
///
/// * [Self::write_all_to_stdio]
/// * [Self::write_to_stdio]
///
///
/// ## Basic error handling
///
/// Creating an encoder with invalid parameters triggers one of the various sanity checks:
///
/// ```rust
/// use rosenpass_util::length_prefix_encoding::encoder::{LengthPrefixEncoder, MessageLenSanityError};
///
/// let message_size = 32;
/// let message = vec![0u8; message_size];
///
/// // The sanity check prevents an unsafe out-of-bounds access here
/// let err = LengthPrefixEncoder::from_short_message(message, 2 * message_size)
///	    .expect_err("OOB access should fail");
/// assert!(matches!(err, MessageLenSanityError::MessageTooLarge(_)));
/// ```

pub struct LengthPrefixEncoder<Buf: Borrow<[u8]>> {
    buf: Buf,
    header: [u8; HEADER_SIZE],
    pos: usize,
}

impl<Buf: Borrow<[u8]>> LengthPrefixEncoder<Buf> {
    /// Creates a new encoder from a buffer
    pub fn from_buffer(buf: Buf) -> Self {
        let (header, pos) = ([0u8; HEADER_SIZE], 0);
        let mut r = Self { buf, header, pos };
        r.clear();
        r
    }

    /// Creates a new encoder using the full buffer as a message
    pub fn from_message(msg: Buf) -> Self {
        let mut r = Self::from_buffer(msg);
        r.restart_write_with_new_message(r.buffer_bytes().len())
            .unwrap();
        r
    }

    /// Creates a new encoder using part of the buffer as a message
    ///
    /// # Example
    ///
    /// See [Basic error handling](#basic-error-handling)
    pub fn from_short_message(msg: Buf, len: usize) -> Result<Self, MessageLenSanityError> {
        let mut r = Self::from_message(msg);
        r.set_message_len(len)?;
        Ok(r)
    }

    /// Creates a new encoder from buffer, message length and write position
    pub fn from_parts(buf: Buf, len: usize, pos: usize) -> Result<Self, SanityError> {
        let mut r = Self::from_buffer(buf);
        r.set_msg_len_and_position(len, pos)?;
        Ok(r)
    }

    /// Consumes the encoder and returns the underlying buffer
    ///
    ///	# Example
    ///
    /// ```rust
    /// use rosenpass_util::length_prefix_encoding::encoder::LengthPrefixEncoder;
    ///
    /// let msg = String::from("hello world");
    /// let encoder = LengthPrefixEncoder::from_message(msg.as_bytes());
    /// let msg_buffer = encoder.into_buffer();
    /// assert_eq!(msg_buffer, msg.as_bytes());
    /// ```
    pub fn into_buffer(self) -> Buf {
        let Self { buf, .. } = self;
        buf
    }

    /// Consumes the encoder and returns buffer, message length and write position
    ///
    ///	# Example
    ///
    /// ```rust
    /// use rosenpass_util::length_prefix_encoding::encoder::LengthPrefixEncoder;
    ///
    /// let msg = String::from("hello world");
    /// let encoder = LengthPrefixEncoder::from_message(msg.as_bytes());
    /// assert!(encoder.encoded_message_bytes() > msg.len());
    /// assert!(!encoder.exhausted());
    ///
    /// let (msg_buffer, msg_length, write_offset) = encoder.into_parts();
    /// assert_eq!(msg_buffer, msg.as_bytes());
    /// assert_eq!(write_offset, 0);
    /// assert_eq!(msg_length, msg.len());
    /// ```
    pub fn into_parts(self) -> (Buf, usize, usize) {
        let len = self.message_len();
        let pos = self.writing_position();
        let buf = self.into_buffer();
        (buf, len, pos)
    }

    /// Resets the encoder state
    pub fn clear(&mut self) {
        self.set_msg_len_and_position(0, 0).unwrap();
        self.set_message_offset(0).unwrap();
    }

    /// Writes the full message to an IO writer, retrying on interrupts
    ///
    /// # Example
    ///
    /// ```rust
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::encoder::{LengthPrefixEncoder, HEADER_SIZE};
    /// let msg = String::from("message in a bottle");
    /// let prefixed_msg_size = msg.len() + HEADER_SIZE;
    ///
    /// let mut encoder = LengthPrefixEncoder::from_message(msg.as_bytes());
    ///
    /// // Fast-forward - behaves as if the HEADER had already been written; only the message remains
    /// encoder
    /// 	.set_header_offset(HEADER_SIZE)
    /// 	.expect("failed to move cursor");
    /// let mut sink = Cursor::new(vec![0; prefixed_msg_size + 1]);
    /// encoder.write_all_to_stdio(&mut sink).expect("write failed");
    /// assert_eq!(&sink.get_ref()[0..msg.len()], msg.as_bytes());
    /// ```
    pub fn write_all_to_stdio<W: io::Write>(&mut self, mut w: W) -> io::Result<()> {
        use io::ErrorKind as K;
        loop {
            match self.write_to_stdio(&mut w).io_err_kind_hint() {
                // Done
                Ok(WriteToIoReturn { done: true, .. }) => break Ok(()),

                // Retry
                Ok(WriteToIoReturn { done: false, .. }) => continue,
                Err((_, K::Interrupted)) => continue,

                Err((e, _)) => break Err(e),
            }
        }
    }

    /// Attempts to write the next chunk of data to an IO writer, returning the number of bytes written and completion flag
    ///
    /// # Example
    ///
    ///	```rust
    /// # use std::io::Cursor;
    /// # use rosenpass_util::length_prefix_encoding::encoder::{LengthPrefixEncoder, WriteToIoReturn, HEADER_SIZE};
    ///	let msg = String::from("Hello world");
    ///	let prefixed_msg_size = msg.len() + HEADER_SIZE;
    ///
    ///	let mut encoder = LengthPrefixEncoder::from_parts(msg.as_bytes(), msg.len(), 0).unwrap();
    ///	assert_eq!(encoder.encoded_message_bytes(), prefixed_msg_size);
    ///	assert!(!encoder.exhausted());
    ///
    ///	let mut dummy_stdout = Cursor::new(vec![0; prefixed_msg_size + 1]);
    ///
    ///	loop {
    ///		let result: WriteToIoReturn = encoder
    ///			.write_to_stdio(&mut dummy_stdout)
    ///			.expect("write failed");
    ///		if dummy_stdout.position() as usize >= prefixed_msg_size {
    ///			// The entire message should've been written (and the encoder state reflect this)
    ///			assert!(result.done);
    ///			assert_eq!(result.bytes_written, msg.len());
    ///			assert_eq!(encoder.header_written(), (msg.len() as u64).to_le_bytes());
    ///			assert_eq!(encoder.message_written(), msg.as_bytes());
    ///			break;
    ///		}
    ///	}
    ///	let buffer_bytes = dummy_stdout.get_ref();
    ///	match String::from_utf8(buffer_bytes.to_vec()) {
    ///		Ok(buffer_str) => assert_eq!(&buffer_str[HEADER_SIZE..prefixed_msg_size], msg),
    ///		Err(err) => println!("Error converting buffer to String: {:?}", err),
    ///	}
    ///	assert_eq!(
    ///		&dummy_stdout.get_ref()[HEADER_SIZE..prefixed_msg_size],
    ///		msg.as_bytes()
    ///	);
    /// ```
    pub fn write_to_stdio<W: io::Write>(&mut self, mut w: W) -> io::Result<WriteToIoReturn> {
        if self.exhausted() {
            return Ok(WriteToIoReturn {
                bytes_written: 0,
                done: true,
            });
        }

        let buf = self.next_slice_to_write();
        let bytes_written = w.write(buf)?;
        self.advance(bytes_written).unwrap();

        let done = self.exhausted();
        Ok(WriteToIoReturn {
            bytes_written,
            done,
        })
    }

    /// Resets write position to start for restarting output
    pub fn restart_write(&mut self) {
        self.set_writing_position(0).unwrap()
    }

    /// Resets write position to start and updates message length for restarting with new data
    pub fn restart_write_with_new_message(
        &mut self,
        len: usize,
    ) -> Result<(), MessageLenSanityError> {
        self.set_msg_len_and_position(len, 0)
            .map_err(|e| e.try_into().unwrap())
    }

    /// Returns the next unwritten slice of data to write from header or message
    pub fn next_slice_to_write(&self) -> &[u8] {
        let s = self.header_left();
        if !s.is_empty() {
            return s;
        }

        let s = self.message_left();
        if !s.is_empty() {
            return s;
        }

        &[]
    }

    /// Returns true if all data including header and message has been written
    pub fn exhausted(&self) -> bool {
        self.next_slice_to_write().is_empty()
    }

    /// Returns slice containing full message data
    pub fn message(&self) -> &[u8] {
        &self.buffer_bytes()[..self.message_len()]
    }

    /// Returns slice containing written portion of length header
    pub fn header_written(&self) -> &[u8] {
        &self.header()[..self.header_offset()]
    }

    /// Returns slice containing unwritten portion of length header
    pub fn header_left(&self) -> &[u8] {
        &self.header()[self.header_offset()..]
    }

    /// Returns slice containing written portion of message data
    pub fn message_written(&self) -> &[u8] {
        &self.message()[..self.message_offset()]
    }

    /// Returns slice containing unwritten portion of message data
    pub fn message_left(&self) -> &[u8] {
        &self.message()[self.message_offset()..]
    }

    /// Returns reference to underlying buffer
    pub fn buf(&self) -> &Buf {
        &self.buf
    }

    /// Returns slice view of underlying buffer bytes
    pub fn buffer_bytes(&self) -> &[u8] {
        self.buf().borrow()
    }

    /// Decodes and returns length header value as u64
    pub fn decode_header(&self) -> u64 {
        u64::from_le_bytes(self.header)
    }

    /// Returns slice containing raw length header bytes
    pub fn header(&self) -> &[u8; HEADER_SIZE] {
        &self.header
    }

    /// Returns decoded message length from header
    pub fn message_len(&self) -> usize {
        self.decode_header() as usize
    }

    /// Returns total encoded size including header and message bytes
    pub fn encoded_message_bytes(&self) -> usize {
        self.message_len() + HEADER_SIZE
    }

    /// Returns current write position within header and message
    pub fn writing_position(&self) -> usize {
        self.pos
    }

    /// Returns write offset within length header bytes
    pub fn header_offset(&self) -> usize {
        min(self.writing_position(), HEADER_SIZE)
    }

    /// Returns write offset within message bytes
    pub fn message_offset(&self) -> usize {
        self.writing_position().saturating_sub(HEADER_SIZE)
    }

    /// Sets new length header bytes with bounds checking
    pub fn set_header(&mut self, header: [u8; HEADER_SIZE]) -> Result<(), MessageLenSanityError> {
        self.offset_transaction(|t| {
            t.header = header;
            t.ensure_msg_in_buf_bounds()?;
            t.ensure_pos_in_msg_bounds()?;
            Ok(())
        })
    }

    /// Encodes and sets length header value with bounds checking
    pub fn encode_and_set_header(&mut self, header: u64) -> Result<(), MessageLenSanityError> {
        self.set_header(header.to_le_bytes())
    }

    /// Sets message lengthwith bounds checking
    pub fn set_message_len(&mut self, len: usize) -> Result<(), MessageLenSanityError> {
        self.encode_and_set_header(len as u64)
    }

    /// Sets write position with message and buffer bounds checking
    pub fn set_writing_position(&mut self, pos: usize) -> Result<(), PositionSanityError> {
        self.offset_transaction(|t| {
            t.pos = pos;
            t.ensure_pos_in_buf_bounds()?;
            t.ensure_pos_in_msg_bounds()?;
            Ok(())
        })
    }

    /// Sets write position within header bytes with bounds checking
    pub fn set_header_offset(&mut self, off: usize) -> Result<(), PositionOutOfHeaderBounds> {
        ensure_or(off <= HEADER_SIZE, PositionOutOfHeaderBounds)?;
        self.set_writing_position(off).unwrap();
        Ok(())
    }

    /// Sets write position within message bytes with bounds checking
    pub fn set_message_offset(&mut self, off: usize) -> Result<(), PositionSanityError> {
        self.set_writing_position(off + HEADER_SIZE)
    }

    /// Advances write position by specified offset with bounds checking
    pub fn advance(&mut self, off: usize) -> Result<(), PositionSanityError> {
        self.set_writing_position(self.writing_position() + off)
    }

    /// Sets message length and write position with bounds checking
    pub fn set_msg_len_and_position(&mut self, len: usize, pos: usize) -> Result<(), SanityError> {
        self.pos = 0;
        self.set_message_len(len)?;
        self.set_writing_position(pos)?;
        Ok(())
    }

    fn offset_transaction<E, F>(&mut self, f: F) -> Result<(), E>
    where
        F: FnOnce(&mut LengthPrefixEncoder<&[u8]>) -> Result<(), E>,
    {
        let (header, pos) = {
            let (buf, header, pos) = (self.buffer_bytes(), self.header, self.pos);
            let mut tmp = LengthPrefixEncoder { buf, header, pos };
            f(&mut tmp)?;
            Ok((tmp.header, tmp.pos))
        }?;
        (self.header, self.pos) = (header, pos);
        Ok(())
    }

    fn ensure_pos_in_buf_bounds(&self) -> Result<(), PositionOutOfBufferBounds> {
        ensure_or(
            self.message_offset() <= self.buffer_bytes().len(),
            PositionOutOfBufferBounds,
        )
    }

    fn ensure_pos_in_msg_bounds(&self) -> Result<(), PositionOutOfMessageBounds> {
        ensure_or(
            self.message_offset() <= self.message_len(),
            PositionOutOfMessageBounds,
        )
    }

    fn ensure_msg_in_buf_bounds(&self) -> Result<(), MessageTooLarge> {
        ensure_or(
            self.message_len() <= self.buffer_bytes().len(),
            MessageTooLarge,
        )
    }
}

impl<Buf: BorrowMut<[u8]>> LengthPrefixEncoder<Buf> {
    /// Gets a mutable reference to the underlying buffer
    pub fn buf_mut(&mut self) -> &mut Buf {
        &mut self.buf
    }

    /// Gets the buffer as mutable bytes
    pub fn buffer_bytes_mut(&mut self) -> &mut [u8] {
        self.buf.borrow_mut()
    }

    /// Gets a mutable reference to the message slice
    pub fn message_mut(&mut self) -> &mut [u8] {
        let off = self.message_len();
        &mut self.buffer_bytes_mut()[..off]
    }

    /// Gets a mutable reference to the written portion of the message
    pub fn message_written_mut(&mut self) -> &mut [u8] {
        let off = self.message_offset();
        &mut self.message_mut()[..off]
    }

    /// Gets a mutable reference to the unwritten portion of the message
    pub fn message_left_mut(&mut self) -> &mut [u8] {
        let off = self.message_offset();
        &mut self.message_mut()[off..]
    }
}

impl<Buf: BorrowMut<[u8]>> Zeroize for LengthPrefixEncoder<Buf> {
    fn zeroize(&mut self) {
        self.buffer_bytes_mut().zeroize();
        self.header.zeroize();
        self.pos.zeroize();
        self.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lpe_error_conversion_upcast_valid() {
        let len_error = MessageTooLarge;
        let len_sanity_error: MessageLenSanityError = len_error.into();

        let sanity_error: SanityError = len_error.into();
        assert!(matches!(sanity_error, SanityError::MessageTooLarge(_)));
        let sanity_error: SanityError = len_sanity_error.into();
        assert!(matches!(sanity_error, SanityError::MessageTooLarge(_)));

        let pos_error = PositionOutOfBufferBounds;
        let pos_sanity_error: PositionSanityError = pos_error.into();

        let sanity_error: SanityError = pos_error.into();
        assert!(matches!(
            sanity_error,
            SanityError::PositionOutOfBufferBounds(_)
        ));

        let sanity_error: SanityError = pos_sanity_error.into();
        assert!(matches!(
            sanity_error,
            SanityError::PositionOutOfBufferBounds(_)
        ));
    }

    #[test]
    fn test_lpe_error_conversion_downcast_invalid() {
        let pos_error = PositionOutOfBufferBounds;
        let sanity_error = SanityError::PositionOutOfBufferBounds(pos_error.into());
        match MessageLenSanityError::try_from(sanity_error) {
            Ok(_) => panic!("Conversion should always fail (incompatible enum variant)"),
            Err(err) => assert!(matches!(err, PositionOutOfBufferBounds)),
        }
    }

    #[test]
    fn test_write_to_stdio_cursor() {
        use std::io::Cursor;

        let msg = String::from("Hello world");
        let prefixed_msg_size = msg.len() + HEADER_SIZE;

        let mut encoder = LengthPrefixEncoder::from_parts(msg.as_bytes(), msg.len(), 0).unwrap();
        assert_eq!(encoder.encoded_message_bytes(), prefixed_msg_size);
        assert!(!encoder.exhausted());

        let mut dummy_stdout = Cursor::new(vec![0; prefixed_msg_size + 1]);

        loop {
            let result: WriteToIoReturn = encoder
                .write_to_stdio(&mut dummy_stdout)
                .expect("write failed");
            if dummy_stdout.position() as usize >= prefixed_msg_size {
                // The entire message should've been written (and the encoder state reflect this)
                assert!(result.done);
                assert_eq!(result.bytes_written, msg.len());
                assert_eq!(encoder.header_written(), (msg.len() as u64).to_le_bytes());
                assert_eq!(encoder.message_written(), msg.as_bytes());
                break;
            }
        }

        let buffer_bytes = dummy_stdout.get_ref();
        match String::from_utf8(buffer_bytes.to_vec()) {
            Ok(buffer_str) => assert_eq!(&buffer_str[HEADER_SIZE..prefixed_msg_size], msg),
            Err(err) => println!("Error converting buffer to String: {:?}", err),
        }
        assert_eq!(
            &dummy_stdout.get_ref()[HEADER_SIZE..prefixed_msg_size],
            msg.as_bytes()
        );
    }

    #[test]
    fn test_write_offset_header() {
        use std::io::Cursor;

        let mut msg = Vec::<u8>::new();
        msg.extend_from_slice(b"cats");
        msg.extend_from_slice(b" and dogs");
        let msg_len = msg.len();
        let prefixed_msg_size = msg_len + HEADER_SIZE;
        msg.extend_from_slice(b" and other animals"); // To be discarded

        let mut encoder = LengthPrefixEncoder::from_short_message(msg.clone(), msg_len).unwrap();
        // Only the short message should have been stored (and the unused part discarded)
        assert_eq!(encoder.message_mut(), b"cats and dogs");
        assert_eq!(encoder.message_written_mut(), []);
        assert_eq!(encoder.message_left_mut(), b"cats and dogs");
        assert_eq!(encoder.buf_mut(), &msg);

        // Fast-forward as if the header had already been sent - only the message remains
        encoder
            .set_header_offset(HEADER_SIZE)
            .expect("failed to move cursor");
        let mut sink = Cursor::new(vec![0; prefixed_msg_size + 1]);
        encoder.write_all_to_stdio(&mut sink).expect("write failed");
        assert_eq!(&sink.get_ref()[0..msg_len], &msg[0..msg_len]);

        assert_eq!(encoder.message_mut(), b"cats and dogs");
        assert_eq!(encoder.message_written_mut(), b"cats and dogs");
        assert_eq!(encoder.message_left_mut(), []);
        assert_eq!(encoder.buf_mut(), &msg);
    }

    #[test]
    fn test_some_assembly_required() {
        let msg = String::from("hello world");
        let encoder = LengthPrefixEncoder::from_message(msg.as_bytes());
        assert!(encoder.encoded_message_bytes() > msg.len());
        assert!(!encoder.exhausted());

        let (msg_buffer, msg_length, write_offset) = encoder.into_parts();
        assert_eq!(msg_buffer, msg.as_bytes());
        assert_eq!(write_offset, 0);
        assert_eq!(msg_length, msg.len());
    }

    #[test]
    fn test_restart_write_reset() {
        let msg = String::from("hello world");
        let mut encoder = LengthPrefixEncoder::from_message(msg.as_bytes());
        assert_eq!(encoder.writing_position(), 0);
        encoder.set_writing_position(4).unwrap();
        assert_eq!(encoder.writing_position(), 4);
        encoder.restart_write();
        assert_eq!(encoder.writing_position(), 0);
    }

    #[test]
    fn test_zeroize_state() {
        use zeroize::Zeroize;

        let mut msg = Vec::<u8>::new();
        msg.extend_from_slice(b"test");
        let mut encoder = LengthPrefixEncoder::from_message(msg.clone());
        assert_eq!(encoder.message(), msg);
        encoder.zeroize();
        assert_eq!(encoder.message(), []);
    }
}
